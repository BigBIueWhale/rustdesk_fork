#!/usr/bin/env python3
import argparse
import copy
import ctypes
import gzip
import hashlib
import io
import json
import os
import re
import signal
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
import xml.etree.ElementTree as ET
from email.parser import BytesParser
from pathlib import Path


POLKIT_ACTION_ID = "com.carriez.RustDesk.set-unattended-password"
POLKIT_POLICY_SOURCE = Path("res/com.carriez.RustDesk.policy")
POLKIT_POLICY_MEMBER = "./usr/share/polkit-1/actions/com.carriez.RustDesk.policy"
POLKIT_POLICY_DEFAULTS = {
    "allow_any": "auth_admin",
    "allow_inactive": "auth_admin",
    "allow_active": "auth_admin",
}
CONFFILE_PATHS = (
    "./etc/init.d/rustdesk",
)
DATA_EXECUTABLES = {
    "./etc/init.d/rustdesk",
    "./usr/share/rustdesk/files/manual/rustdesk-service",
    "./usr/share/rustdesk/files/openrc/rustdesk",
    "./usr/share/rustdesk/files/runit/run",
    "./usr/share/rustdesk/rustdesk",
    "./usr/share/rustdesk/rustdesk-service-child",
}
FLUTTER_LIBRARIES = {
    "./usr/share/rustdesk/lib/libapp.so",
    "./usr/share/rustdesk/lib/libdesktop_drop_plugin.so",
    "./usr/share/rustdesk/lib/libdesktop_multi_window_plugin.so",
    "./usr/share/rustdesk/lib/libflutter_custom_cursor_plugin.so",
    "./usr/share/rustdesk/lib/libflutter_linux_gtk.so",
    "./usr/share/rustdesk/lib/librustdesk.so",
    "./usr/share/rustdesk/lib/libscreen_retriever_plugin.so",
    "./usr/share/rustdesk/lib/libtexture_rgba_renderer_plugin.so",
    "./usr/share/rustdesk/lib/liburl_launcher_linux_plugin.so",
    "./usr/share/rustdesk/lib/libwindow_manager_plugin.so",
    "./usr/share/rustdesk/lib/libwindow_size_plugin.so",
}
DATA_REQUIRED_DIRECTORIES = {
    ".",
    "./etc",
    "./etc/init.d",
    "./usr",
    "./usr/bin",
    "./usr/lib",
    "./usr/lib/rustdesk-fork",
    "./usr/lib/systemd",
    "./usr/lib/systemd/system",
    "./usr/share",
    "./usr/share/applications",
    "./usr/share/icons",
    "./usr/share/icons/hicolor",
    "./usr/share/icons/hicolor/256x256",
    "./usr/share/icons/hicolor/256x256/apps",
    "./usr/share/icons/hicolor/scalable",
    "./usr/share/icons/hicolor/scalable/apps",
    "./usr/share/polkit-1",
    "./usr/share/polkit-1/actions",
    "./usr/share/rustdesk",
    "./usr/share/rustdesk/data",
    "./usr/share/rustdesk/data/flutter_assets",
    "./usr/share/rustdesk/files",
    "./usr/share/rustdesk/files/manual",
    "./usr/share/rustdesk/files/openrc",
    "./usr/share/rustdesk/files/runit",
    "./usr/share/rustdesk/lib",
}
DATA_REQUIRED_FILES = {
    "./etc/init.d/rustdesk",
    "./usr/lib/systemd/system/rustdesk.service",
    "./usr/lib/rustdesk-fork/libxdo.so.3",
    "./usr/share/applications/rustdesk-link.desktop",
    "./usr/share/applications/rustdesk.desktop",
    "./usr/share/icons/hicolor/256x256/apps/rustdesk.png",
    "./usr/share/icons/hicolor/scalable/apps/rustdesk.svg",
    POLKIT_POLICY_MEMBER,
    "./usr/share/rustdesk/data/flutter_assets/AssetManifest.bin",
    "./usr/share/rustdesk/data/flutter_assets/FontManifest.json",
    "./usr/share/rustdesk/data/flutter_assets/NOTICES.Z",
    "./usr/share/rustdesk/data/icudtl.dat",
    "./usr/share/rustdesk/files/manual/rustdesk-service",
    "./usr/share/rustdesk/files/openrc/rustdesk",
    "./usr/share/rustdesk/files/runit/run",
    "./usr/share/rustdesk/files/native-xdo-COPYRIGHT",
    "./usr/share/rustdesk/files/native-xdo-SOURCE.txt",
    "./usr/share/rustdesk/rustdesk",
    "./usr/share/rustdesk/rustdesk-service-child",
}
DATA_REQUIRED_FILES.update(FLUTTER_LIBRARIES)
DATA_REQUIRED_SYMLINKS = {
    "./usr/bin/rustdesk": "../share/rustdesk/rustdesk",
}
DATA_VARIABLE_ROOT = "./usr/share/rustdesk/data/flutter_assets"
PRIMARY_BINARY = "./usr/share/rustdesk/rustdesk"
SERVICE_CHILD_BINARY = "./usr/share/rustdesk/rustdesk-service-child"
RUNNER_BINARIES = {PRIMARY_BINARY, SERVICE_CHILD_BINARY}
NATIVE_XDO_LIBRARY = "./usr/lib/rustdesk-fork/libxdo.so.3"
MANDATORY_ELVES = RUNNER_BINARIES | FLUTTER_LIBRARIES | {NATIVE_XDO_LIBRARY}
DATA_REQUIRED = {
    name: ("dir", 0o755) for name in DATA_REQUIRED_DIRECTORIES
}
DATA_REQUIRED.update({
    name: (
        "file",
        0o711
        if name == SERVICE_CHILD_BINARY
        else 0o755
        if name in DATA_EXECUTABLES
        else 0o644,
    )
    for name in DATA_REQUIRED_FILES
})
CONTROL_REQUIRED = {
    "./control": ("file", 0o644),
    "./conffiles": ("file", 0o644),
    "./md5sums": ("file", 0o644),
    "./preinst": ("file", 0o755),
    "./postinst": ("file", 0o755),
    "./prerm": ("file", 0o755),
    "./postrm": ("file", 0o755),
}
DYNAMIC_STRING_TAGS = {
    1: "NEEDED",
    14: "SONAME",
    15: "RPATH",
    29: "RUNPATH",
    0x6FFFFEFA: "CONFIG",
    0x6FFFFEFB: "DEPAUDIT",
    0x6FFFFEFC: "AUDIT",
    0x7FFFFFFD: "AUXILIARY",
    0x7FFFFFFF: "FILTER",
}
FORBIDDEN_DYNAMIC_LOADER_TAGS = {
    0x6FFFFEFA,
    0x6FFFFEFB,
    0x6FFFFEFC,
    0x7FFFFFFD,
    0x7FFFFFFF,
}
SAFE_NEEDED_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+@-]*\Z")
EXPECTED_PROGRAM_INTERPRETER = b"/lib64/ld-linux-x86-64.so.2\0"


class ValidationError(Exception):
    pass


def fail(message):
    print(f"FAIL Debian package authority: {message}", file=sys.stderr)
    sys.exit(1)


def xml_tag_name(tag):
    return tag.rsplit("}", 1)[-1]


def validate_polkit_policy(contents, label):
    try:
        root = ET.fromstring(contents)
    except ET.ParseError as err:
        raise ValidationError(f"{label}: XML parse failed: {err}") from err
    if xml_tag_name(root.tag) != "policyconfig":
        raise ValidationError(f"{label}: root element is not policyconfig")

    actions = [child for child in root if xml_tag_name(child.tag) == "action"]
    if len(actions) != 1:
        raise ValidationError(f"{label}: expected exactly one action, found {len(actions)}")
    action = actions[0]
    if action.get("id") != POLKIT_ACTION_ID:
        raise ValidationError(f"{label}: unexpected action id {action.get('id')!r}")

    defaults = [child for child in action if xml_tag_name(child.tag) == "defaults"]
    if len(defaults) != 1:
        raise ValidationError(
            f"{label}: expected exactly one defaults block, found {len(defaults)}"
        )
    entries = [
        (xml_tag_name(child.tag), (child.text or "").strip())
        for child in defaults[0]
    ]
    values = dict(entries)
    if len(entries) != len(POLKIT_POLICY_DEFAULTS) or values != POLKIT_POLICY_DEFAULTS:
        raise ValidationError(
            f"{label}: defaults are {entries!r}, expected {POLKIT_POLICY_DEFAULTS!r}"
        )


def load_polkit_policy(repo):
    path = repo / POLKIT_POLICY_SOURCE
    try:
        contents = path.read_bytes()
    except OSError as err:
        raise ValidationError(f"cannot read {POLKIT_POLICY_SOURCE}: {err}") from err
    validate_polkit_policy(contents, str(POLKIT_POLICY_SOURCE))
    return contents


def normalize_tar_name(name):
    if name.endswith("/"):
        name = name[:-1]
    if name == ".":
        return "."
    if name.startswith("./"):
        return name
    return f"./{name}"


def is_under(name, prefix):
    return name == prefix or name.startswith(f"{prefix}/")


def canonical_tar_text_field(field, label):
    nul = field.find(b"\0")
    if nul < 0:
        return field
    if any(field[nul + 1:]):
        raise ValidationError(f"{label}: tar text field has nonzero bytes after NUL")
    return field[:nul]


def raw_tar_member_name(archive, member, label):
    if member.pax_headers:
        raise ValidationError(f"{label}: extended tar path metadata is forbidden")
    archive.fileobj.seek(member.offset)
    header = archive.fileobj.read(512)
    if len(header) != 512:
        raise ValidationError(f"{label}: archive member header is truncated")
    type_flag = header[156:157]
    if member.isdir():
        expected_type = tarfile.DIRTYPE
    elif member.isfile():
        expected_type = tarfile.REGTYPE
    else:
        expected_type = member.type
    if type_flag != expected_type:
        raise ValidationError(f"{label}: extended or mismatched tar member header is forbidden")

    name_bytes = canonical_tar_text_field(header[:100], f"{label}:name")
    link_bytes = canonical_tar_text_field(header[157:257], f"{label}:linkname")
    user_bytes = canonical_tar_text_field(header[265:297], f"{label}:uname")
    group_bytes = canonical_tar_text_field(header[297:329], f"{label}:gname")
    prefix_bytes = canonical_tar_text_field(header[345:500], f"{label}:prefix")
    if (member.isfile() or member.isdir()) and link_bytes:
        raise ValidationError(f"{label}: regular file or directory has a nonempty tar link name")
    if member.issym():
        try:
            decoded_link = link_bytes.decode("utf-8")
        except UnicodeDecodeError as err:
            raise ValidationError(f"{label}: symbolic-link target is not UTF-8") from err
        if member.linkname != decoded_link:
            raise ValidationError(f"{label}: tar parser normalized the symbolic-link target")
    if user_bytes != b"root" or group_bytes != b"root":
        raise ValidationError(f"{label}: tar owner names are not canonical root/root")
    if prefix_bytes:
        name_bytes = prefix_bytes + b"/" + name_bytes
    try:
        return name_bytes.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ValidationError(f"{label}: archive member name is not UTF-8") from err


def tar_members_from_stream(data, label):
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            members = {}
            for member in archive.getmembers():
                stored_name = raw_tar_member_name(archive, member, label)
                if stored_name.startswith("/"):
                    raise ValidationError(f"{label}: archive member has an absolute name: {stored_name!r}")
                if stored_name == "./":
                    if not member.isdir():
                        raise ValidationError(f"{label}: archive root is not a directory")
                    name = "."
                else:
                    if not stored_name.startswith("./"):
                        raise ValidationError(
                            f"{label}: archive member lacks the canonical ./ prefix: {stored_name!r}"
                        )
                    if stored_name.endswith("/"):
                        if not member.isdir():
                            raise ValidationError(
                                f"{label}: non-directory archive member has a trailing slash: {stored_name!r}"
                            )
                        if stored_name.endswith("//"):
                            raise ValidationError(
                                f"{label}: directory archive member has redundant trailing slashes: {stored_name!r}"
                            )
                        raw_name = stored_name[:-1]
                    elif member.isdir():
                        raise ValidationError(
                            f"{label}: directory archive member lacks its canonical trailing slash: {stored_name!r}"
                        )
                    else:
                        raw_name = stored_name
                    if any(character in raw_name for character in ("\n", "\r", "\0")):
                        raise ValidationError(f"{label}: archive member has an unsupported name")
                    relative = raw_name[2:]
                    if not relative or any(part in ("", ".", "..") for part in relative.split("/")):
                        raise ValidationError(f"{label}: archive member has a non-canonical name: {stored_name!r}")
                    name = raw_name
                if member.name != name:
                    raise ValidationError(
                        f"{label}: tar parser normalized {stored_name!r} to unexpected {member.name!r}"
                    )
                if name in members:
                    raise ValidationError(f"{label}: duplicate archive member: {name}")
                members[name] = member
            return members
    except tarfile.TarError as err:
        raise ValidationError(f"{label}: failed to read tar stream: {err}") from err


def tar_members_from_deb(deb, option):
    return tar_members_from_stream(tar_stream_from_deb(deb, option), f"{deb}:{option}")


def tar_stream_from_deb(deb, option):
    if shutil.which("dpkg-deb") is None:
        raise ValidationError("dpkg-deb is required")
    try:
        return subprocess.check_output(["dpkg-deb", option, str(deb)])
    except subprocess.CalledProcessError as err:
        raise ValidationError(f"{deb}: dpkg-deb {option} failed with status {err.returncode}") from err


def require_root_owned(member, label):
    if member.uid != 0 or member.gid != 0:
        raise ValidationError(f"{label}: owner is {member.uid}/{member.gid}, expected 0/0")


def require_member(members, path, expected_kind, expected_mode, label):
    member = members.get(path)
    if member is None:
        raise ValidationError(f"{label}: missing required archive member {path}")
    require_root_owned(member, f"{label}:{path}")
    if expected_kind == "dir" and not member.isdir():
        raise ValidationError(f"{label}:{path}: expected directory")
    if expected_kind == "file" and not member.isfile():
        raise ValidationError(f"{label}:{path}: expected regular file")
    if member.mode != expected_mode:
        raise ValidationError(f"{label}:{path}: mode {member.mode:o}, expected {expected_mode:o}")


def require_symlink(members, path, expected_target, label):
    member = members.get(path)
    if member is None:
        raise ValidationError(f"{label}: missing required archive member {path}")
    require_root_owned(member, f"{label}:{path}")
    if not member.issym():
        raise ValidationError(f"{label}:{path}: expected symbolic link")
    if member.mode != 0o777:
        raise ValidationError(f"{label}:{path}: mode {member.mode:o}, expected 777")
    if member.linkname != expected_target:
        raise ValidationError(
            f"{label}:{path}: target {member.linkname!r}, expected {expected_target!r}"
        )


def validate_data_members(members, label):
    for name, member in members.items():
        require_root_owned(member, f"{label}:{name}")
        expected = (
            0o777
            if member.issym()
            else 0o755
            if member.isdir()
            else 0o711
            if name == SERVICE_CHILD_BINARY
            else 0o755
            if name in DATA_EXECUTABLES
            else 0o644
        )
        if not member.isfile() and not member.isdir() and not member.issym():
            raise ValidationError(
                f"{label}:{name}: package tree must contain only regular files, directories, and the exact command symlink"
            )
        if member.mode != expected:
            raise ValidationError(f"{label}:{name}: mode {member.mode:o}, expected {expected:o}")

    directories = {name for name, member in members.items() if member.isdir()}
    files = {name for name, member in members.items() if member.isfile()}
    symlinks = {
        name: member.linkname for name, member in members.items() if member.issym()
    }
    missing_directories = DATA_REQUIRED_DIRECTORIES - directories
    missing_files = DATA_REQUIRED_FILES - files
    missing_symlinks = set(DATA_REQUIRED_SYMLINKS) - set(symlinks)
    unexpected_directories = {
        name for name in directories
        if name not in DATA_REQUIRED_DIRECTORIES
        and not is_under(name, DATA_VARIABLE_ROOT)
    }
    unexpected_files = {
        name for name in files
        if name not in DATA_REQUIRED_FILES
        and not is_under(name, DATA_VARIABLE_ROOT)
    }
    unexpected_symlinks = set(symlinks) - set(DATA_REQUIRED_SYMLINKS)
    wrong_symlinks = {
        name: target
        for name, target in symlinks.items()
        if DATA_REQUIRED_SYMLINKS.get(name) != target
    }
    if (missing_directories or missing_files or missing_symlinks
            or unexpected_directories or unexpected_files or unexpected_symlinks
            or wrong_symlinks):
        raise ValidationError(
            f"{label}: data inventory differs: "
            f"missing directories {sorted(missing_directories)}, "
            f"missing files {sorted(missing_files)}, "
            f"missing symlinks {sorted(missing_symlinks)}, "
            f"unexpected directories {sorted(unexpected_directories)}, "
            f"unexpected files {sorted(unexpected_files)}, "
            f"unexpected symlinks {sorted(unexpected_symlinks)}, "
            f"wrong symlinks {sorted(wrong_symlinks.items())}"
        )


def validate_control_members(members, label):
    expected_names = {".", *CONTROL_REQUIRED}
    if set(members) != expected_names:
        raise ValidationError(
            f"{label}: control inventory differs: {sorted(set(members) - expected_names)} extra, "
            f"{sorted(expected_names - set(members))} missing"
        )
    root = members["."]
    require_root_owned(root, f"{label}:.")
    if not root.isdir() or root.mode != 0o755:
        raise ValidationError(f"{label}:.: expected mode-755 directory")


def expected_elf_runpath(name):
    basename = Path(name).name
    if name in RUNNER_BINARIES:
        return ("$ORIGIN/lib",)
    if is_under(name, "./usr/share/rustdesk/lib") and (
        basename == "libflutter_linux_gtk.so" or basename.endswith("_plugin.so")
    ):
        return ("$ORIGIN",)
    return ()


def dynamic_string_values(dynamic_entries, string_table, label):
    if not string_table or string_table[0] != 0 or string_table[-1] != 0:
        raise ValidationError(f"{label}: ELF dynamic string table must begin and end with NUL")
    values = {}
    for tag, offset in dynamic_entries:
        name = DYNAMIC_STRING_TAGS.get(tag)
        if name is None:
            continue
        if offset >= len(string_table):
            raise ValidationError(f"{label}: {name} string offset is out of bounds")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise ValidationError(f"{label}: {name} string is not NUL-terminated")
        try:
            value = string_table[offset:end].decode("ascii")
        except UnicodeDecodeError as err:
            raise ValidationError(f"{label}: {name} string is not ASCII") from err
        values.setdefault(tag, []).append(value)
    return values


def dynamic_runpath(dynamic_entries, string_table, name, label):
    values = dynamic_string_values(dynamic_entries, string_table, label)
    forbidden = sorted(
        DYNAMIC_STRING_TAGS[tag]
        for tag in FORBIDDEN_DYNAMIC_LOADER_TAGS
        if tag in values
    )
    if forbidden:
        raise ValidationError(f"{label}: forbidden dynamic loader tags are present: {forbidden}")

    for needed in values.get(1, []):
        if SAFE_NEEDED_NAME.fullmatch(needed) is None:
            raise ValidationError(f"{label}: NEEDED is not a safe dependency basename: {needed!r}")
    sonames = values.get(14, [])
    if len(sonames) > 1:
        raise ValidationError(f"{label}: multiple SONAME entries are forbidden")
    if sonames and sonames[0] != Path(name).name:
        raise ValidationError(
            f"{label}: SONAME {sonames[0]!r} does not match the installed basename {Path(name).name!r}"
        )

    rpaths = values.get(15, [])
    runpaths = values.get(29, [])
    if rpaths:
        raise ValidationError(f"{label}: legacy RPATH is forbidden")
    if len(runpaths) > 1:
        raise ValidationError(f"{label}: multiple RUNPATH entries are forbidden")
    if not runpaths:
        return (), False
    value = runpaths[0]
    return tuple(value.split(":")) if value else (), True


def validate_runpath_policy(actual, present, name, label):
    expected = expected_elf_runpath(name)
    if actual != expected or present != bool(expected):
        raise ValidationError(
            f"{label}: unexpected RUNPATH {actual!r} "
            f"(present={present}), expected {expected!r}"
        )


def validate_elf_identity(contents, name, label):
    if len(contents) < 64:
        raise ValidationError(f"{label}: ELF header is truncated")
    if contents[4] != 2:
        raise ValidationError(f"{label}: ELF class is not 64-bit")
    if contents[5] != 1:
        raise ValidationError(f"{label}: ELF byte order is not little-endian")
    if contents[6] != 1:
        raise ValidationError(f"{label}: ELF identification version is not current")
    try:
        (
            elf_type,
            machine,
            version,
            entry,
            program_offset,
            _section_offset,
            _flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _section_name_index,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", contents, 16)
    except struct.error as err:
        raise ValidationError(f"{label}: ELF header cannot be decoded") from err
    if version != 1 or header_size != 64:
        raise ValidationError(f"{label}: ELF header version or size is invalid")
    if machine != 62:
        raise ValidationError(f"{label}: ELF machine is not x86-64")
    expected_types = (2, 3) if name in RUNNER_BINARIES else (3,)
    if elf_type not in expected_types:
        expected_text = "ET_EXEC or ET_DYN" if len(expected_types) == 2 else "ET_DYN"
        raise ValidationError(f"{label}: ELF type is {elf_type}, expected {expected_text}")
    if program_count == 0 or program_count == 0xffff or program_entry_size != 56:
        raise ValidationError(f"{label}: ELF program-header table is absent or unsupported")
    program_table_end = program_offset + program_entry_size * program_count
    if program_offset < header_size or program_table_end > len(contents):
        raise ValidationError(f"{label}: ELF program-header table is out of bounds")
    load_segments = []
    dynamic_segments = []
    interpreter_segments = []
    stack_segments = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        try:
            (
                segment_type,
                segment_flags,
                file_offset,
                virtual_address,
                physical_address,
                file_size,
                memory_size,
                align,
            ) = struct.unpack_from("<IIQQQQQQ", contents, offset)
        except struct.error as err:
            raise ValidationError(f"{label}: ELF program header cannot be decoded") from err
        if segment_type == 1:
            if file_size > memory_size or file_offset + file_size > len(contents):
                raise ValidationError(f"{label}: ELF load segment is out of bounds")
            if segment_flags & 1 and segment_flags & 2:
                raise ValidationError(f"{label}: ELF load segment is writable and executable")
            if (align not in (0, 1)
                    and (align & (align - 1) != 0 or file_offset % align != virtual_address % align)):
                raise ValidationError(f"{label}: ELF load segment alignment is invalid")
            load_segments.append((file_offset, virtual_address, file_size, segment_flags))
        elif segment_type == 2:
            dynamic_segments.append((file_offset, virtual_address, file_size, memory_size, align))
        elif segment_type == 3:
            interpreter_segments.append(
                (file_offset, virtual_address, file_size, memory_size, segment_flags, align)
            )
        elif segment_type == 0x6474E551:
            stack_segments.append((
                file_offset,
                virtual_address,
                physical_address,
                file_size,
                memory_size,
                segment_flags,
                align,
            ))

    if name in RUNNER_BINARIES:
        entry_loads = [
            segment for segment in load_segments
            if segment[1] <= entry < segment[1] + segment[2]
        ]
        if entry == 0 or len(entry_loads) != 1 or not entry_loads[0][3] & 1:
            raise ValidationError(f"{label}: ELF runner entry is not in one file-backed executable load segment")
        if len(interpreter_segments) != 1:
            raise ValidationError(f"{label}: ELF runner must contain exactly one program interpreter")
        (
            interpreter_offset,
            interpreter_address,
            interpreter_size,
            interpreter_memory_size,
            interpreter_flags,
            interpreter_align,
        ) = interpreter_segments[0]
        if (interpreter_size != len(EXPECTED_PROGRAM_INTERPRETER)
                or interpreter_memory_size != interpreter_size
                or interpreter_flags != 4
                or interpreter_align != 1
                or interpreter_offset + interpreter_size > len(contents)
                or contents[interpreter_offset:interpreter_offset + interpreter_size] != EXPECTED_PROGRAM_INTERPRETER):
            raise ValidationError(f"{label}: ELF runner program interpreter is not exact")
        interpreter_loads = [
            segment for segment in load_segments
            if interpreter_offset >= segment[0]
            and interpreter_offset + interpreter_size <= segment[0] + segment[2]
            and interpreter_address >= segment[1]
            and interpreter_address + interpreter_size <= segment[1] + segment[2]
            and interpreter_offset - segment[0] == interpreter_address - segment[1]
        ]
        if len(interpreter_loads) != 1:
            raise ValidationError(f"{label}: ELF runner program interpreter is not consistently mapped")
    elif interpreter_segments:
        raise ValidationError(f"{label}: ELF shared object contains a program interpreter")

    if len(stack_segments) != 1:
        raise ValidationError(f"{label}: ELF must contain exactly one GNU stack header")
    (
        stack_offset,
        stack_address,
        stack_physical_address,
        stack_file_size,
        stack_memory_size,
        stack_flags,
        stack_align,
    ) = stack_segments[0]
    if (stack_offset != 0
            or stack_address != 0
            or stack_physical_address != 0
            or stack_file_size != 0
            or stack_memory_size != 0):
        raise ValidationError(f"{label}: ELF GNU stack header must not describe file or memory contents")
    if stack_flags != 6:
        raise ValidationError(f"{label}: ELF GNU stack permissions are not exact non-executable RW")
    if stack_align not in (0, 1) and stack_align & (stack_align - 1) != 0:
        raise ValidationError(f"{label}: ELF GNU stack alignment is not ABI-valid")
    if len(dynamic_segments) != 1:
        raise ValidationError(f"{label}: ELF must contain exactly one dynamic segment")
    dynamic_offset, dynamic_address, dynamic_size, dynamic_memory_size, dynamic_align = dynamic_segments[0]
    if (dynamic_size < 16
            or dynamic_size % 16 != 0
            or dynamic_size > dynamic_memory_size
            or dynamic_offset + dynamic_size > len(contents)):
        raise ValidationError(f"{label}: ELF dynamic segment is out of bounds")
    if (dynamic_align != 8
            or dynamic_offset % dynamic_align != dynamic_address % dynamic_align):
        raise ValidationError(f"{label}: ELF dynamic segment does not have canonical 8-byte alignment")
    dynamic_loads = [
        segment for segment in load_segments
        if dynamic_offset >= segment[0]
        and dynamic_offset + dynamic_size <= segment[0] + segment[2]
        and dynamic_address >= segment[1]
        and dynamic_address + dynamic_size <= segment[1] + segment[2]
        and dynamic_offset - segment[0] == dynamic_address - segment[1]
    ]
    if len(dynamic_loads) != 1:
        raise ValidationError(f"{label}: ELF dynamic segment is not consistently mapped by one load segment")

    dynamic_entries = []
    terminated = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        try:
            tag, value = struct.unpack_from("<QQ", contents, offset)
        except struct.error as err:
            raise ValidationError(f"{label}: ELF dynamic entry cannot be decoded") from err
        if terminated:
            if tag != 0 or value != 0:
                raise ValidationError(f"{label}: ELF dynamic segment has data after DT_NULL")
            continue
        if tag == 0:
            if value != 0:
                raise ValidationError(f"{label}: ELF DT_NULL entry has a nonzero value")
            terminated = True
        else:
            dynamic_entries.append((tag, value))
    if not terminated:
        raise ValidationError(f"{label}: ELF dynamic segment is not DT_NULL-terminated")

    if name not in RUNNER_BINARIES and any(
        tag == 0x6FFFFFFB and value & 0x08000000 for tag, value in dynamic_entries
    ):
        raise ValidationError(f"{label}: ELF shared object is marked DF_1_PIE")

    string_addresses = [value for tag, value in dynamic_entries if tag == 5]
    string_sizes = [value for tag, value in dynamic_entries if tag == 10]
    if len(string_addresses) != 1 or len(string_sizes) != 1 or string_sizes[0] == 0:
        raise ValidationError(f"{label}: ELF must contain one bounded dynamic string table")
    string_address = string_addresses[0]
    string_size = string_sizes[0]
    string_loads = [
        segment for segment in load_segments
        if string_address >= segment[1]
        and string_address + string_size <= segment[1] + segment[2]
    ]
    if len(string_loads) != 1:
        raise ValidationError(f"{label}: ELF dynamic string table is not mapped by one load segment")
    string_load = string_loads[0]
    string_offset = string_load[0] + (string_address - string_load[1])
    if string_offset + string_size > len(contents):
        raise ValidationError(f"{label}: ELF dynamic string table is out of bounds")
    string_table = contents[string_offset:string_offset + string_size]
    return dynamic_runpath(dynamic_entries, string_table, name, label)


def validate_elf_runpaths(deb, data_tar, members):
    try:
        with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:*") as archive:
            runner_contents = {}
            for name, member in sorted(members.items()):
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValidationError(f"{deb}:data:{name}: cannot read archive member")
                contents = extracted.read()
                is_elf = contents.startswith(b"\x7fELF")
                if name in MANDATORY_ELVES and not is_elf:
                    raise ValidationError(f"{deb}:data:{name}: required runtime object is not ELF")
                if not is_elf:
                    continue
                if name in RUNNER_BINARIES:
                    runner_contents[name] = contents
                actual, present = validate_elf_identity(contents, name, f"{deb}:data:{name}")
                validate_runpath_policy(actual, present, name, f"{deb}:data:{name}")
            if runner_contents.get(PRIMARY_BINARY) != runner_contents.get(SERVICE_CHILD_BINARY):
                raise ValidationError(
                    f"{deb}:data: service-child executable is not byte-identical to the primary runner"
                )
    except tarfile.TarError as err:
        raise ValidationError(f"{deb}: failed to inspect data archive ELF runpaths: {err}") from err


def archive_member_bytes(archive_data, member, label):
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:*") as archive:
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValidationError(f"{label}: cannot read archive member")
            return extracted.read()
    except tarfile.TarError as err:
        raise ValidationError(f"{label}: failed to read archive member: {err}") from err


def validate_conffiles(control_tar, control_members, label):
    contents = archive_member_bytes(
        control_tar,
        control_members["./conffiles"],
        f"{label}:./conffiles",
    )
    expected = "".join(f"{name[1:]}\n" for name in CONFFILE_PATHS).encode("ascii")
    if contents != expected:
        raise ValidationError(f"{label}:./conffiles: content differs from the exact configuration inventory")


def validate_md5sums(data_tar, data_members, control_tar, control_members, label):
    contents = archive_member_bytes(
        control_tar,
        control_members["./md5sums"],
        f"{label}:control:./md5sums",
    )
    try:
        text = contents.decode("ascii")
    except UnicodeDecodeError as err:
        raise ValidationError(f"{label}:control:./md5sums: content is not ASCII") from err
    if not text.endswith("\n"):
        raise ValidationError(f"{label}:control:./md5sums: missing final newline")

    recorded = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{32})  (/[^\r\n]+)", line)
        if match is None:
            raise ValidationError(f"{label}:control:./md5sums: malformed line")
        name = f".{match.group(2)}"
        if name in recorded:
            raise ValidationError(f"{label}:control:./md5sums: duplicate path {name}")
        recorded[name] = match.group(1)

    expected_names = {
        name for name, member in data_members.items()
        if member.isfile() and name not in CONFFILE_PATHS
    }
    if set(recorded) != expected_names:
        raise ValidationError(
            f"{label}:control:./md5sums: inventory differs: "
            f"{sorted(set(recorded) - expected_names)} extra, "
            f"{sorted(expected_names - set(recorded))} missing"
        )

    try:
        with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:*") as archive:
            for name in sorted(expected_names):
                extracted = archive.extractfile(data_members[name])
                if extracted is None:
                    raise ValidationError(f"{label}:data:{name}: cannot read for md5sums verification")
                digest = hashlib.md5()
                for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                    digest.update(chunk)
                if digest.hexdigest() != recorded[name]:
                    raise ValidationError(f"{label}:control:./md5sums: digest differs for {name}")
    except tarfile.TarError as err:
        raise ValidationError(f"{label}: failed to verify md5sums: {err}") from err


def validate_polkit_dependency(contents, label):
    control = BytesParser().parsebytes(contents, headersonly=True)
    dependencies = control.get_all("Depends", [])
    if (len(dependencies) != 1
            or "polkitd" not in {group.strip() for group in dependencies[0].split(",")}):
        raise ValidationError(f"{label}: required standalone polkitd dependency is absent")


def validate_deb(deb, expected_systemd_unit=None, expected_polkit_policy=None):
    data_tar = tar_stream_from_deb(deb, "--fsys-tarfile")
    data_members = tar_members_from_stream(data_tar, f"{deb}:--fsys-tarfile")
    control_tar = tar_stream_from_deb(deb, "--ctrl-tarfile")
    control_members = tar_members_from_stream(control_tar, f"{deb}:--ctrl-tarfile")
    validate_data_members(data_members, f"{deb}:data")
    validate_control_members(control_members, f"{deb}:control")
    validate_polkit_dependency(
        archive_member_bytes(control_tar, control_members["./control"], f"{deb}:control:./control"),
        f"{deb}:control:./control",
    )
    for path, (kind, mode) in DATA_REQUIRED.items():
        require_member(data_members, path, kind, mode, f"{deb}:data")
    for path, target in DATA_REQUIRED_SYMLINKS.items():
        require_symlink(data_members, path, target, f"{deb}:data")
    for path, (kind, mode) in CONTROL_REQUIRED.items():
        require_member(control_members, path, kind, mode, f"{deb}:control")
    validate_conffiles(control_tar, control_members, f"{deb}:control")
    if expected_systemd_unit is not None:
        actual_systemd_unit = archive_member_bytes(
            data_tar,
            data_members["./usr/lib/systemd/system/rustdesk.service"],
            f"{deb}:data:./usr/lib/systemd/system/rustdesk.service",
        )
        if actual_systemd_unit != expected_systemd_unit:
            raise ValidationError(
                f"{deb}:data:./usr/lib/systemd/system/rustdesk.service: bytes differ from res/rustdesk.service"
            )
    actual_polkit_policy = archive_member_bytes(
        data_tar,
        data_members[POLKIT_POLICY_MEMBER],
        f"{deb}:data:{POLKIT_POLICY_MEMBER}",
    )
    validate_polkit_policy(
        actual_polkit_policy,
        f"{deb}:data:{POLKIT_POLICY_MEMBER}",
    )
    if (expected_polkit_policy is not None
            and actual_polkit_policy != expected_polkit_policy):
        raise ValidationError(
            f"{deb}:data:{POLKIT_POLICY_MEMBER}: bytes differ from {POLKIT_POLICY_SOURCE}"
        )
    validate_elf_runpaths(deb, data_tar, data_members)
    validate_md5sums(data_tar, data_members, control_tar, control_members, str(deb))


def write_file(path, contents, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    path.chmod(mode)


def make_synthetic_tree(root, polkit_policy):
    write_file(
        root / "DEBIAN/control",
        "Package: rustdesk-authority-test\nVersion: 1.0\nArchitecture: all\nMaintainer: test <test@example.invalid>\nDepends: polkitd\nDescription: authority test\n",
        0o644,
    )
    write_file(
        root / "DEBIAN/conffiles",
        "".join(f"{name[1:]}\n" for name in CONFFILE_PATHS),
        0o644,
    )
    write_file(root / "DEBIAN/md5sums", "", 0o644)
    for script in ("preinst", "postinst", "prerm", "postrm"):
        write_file(root / f"DEBIAN/{script}", "#!/bin/sh\nset -e\nexit 0\n", 0o755)
    for name in sorted(DATA_REQUIRED_FILES):
        path = root / name[2:]
        if name == "./usr/share/rustdesk/rustdesk":
            contents = "#!/bin/sh\nexit 0\n"
        elif name == "./usr/lib/systemd/system/rustdesk.service":
            contents = "[Service]\nExecStart=/usr/bin/rustdesk --service\n"
        elif name == POLKIT_POLICY_MEMBER:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(polkit_policy)
            path.chmod(DATA_REQUIRED[name][1])
            continue
        else:
            contents = f"synthetic fixture for {name}\n"
        write_file(path, contents, DATA_REQUIRED[name][1])
    for name in sorted(DATA_REQUIRED_DIRECTORIES, key=lambda item: item.count("/"), reverse=True):
        path = root if name == "." else root / name[2:]
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
    for name, target in sorted(DATA_REQUIRED_SYMLINKS.items()):
        (root / name[2:]).symlink_to(target)
    (root / "DEBIAN").chmod(0o755)
    root.chmod(0o755)


def build_synthetic_elf(path, runpath=None, shared=False, legacy_rpath=False):
    if shutil.which("cc") is None:
        raise ValidationError("cc is required for ELF RUNPATH self-test")
    with tempfile.TemporaryDirectory(prefix="rustdesk-elf-src.") as tmp:
        source = Path(tmp) / "synthetic.c"
        if shared:
            source.write_text("int rustdesk_synthetic_symbol(void) { return 0; }\n", encoding="utf-8")
            cmd = ["cc", "-shared", "-fPIC", str(source), "-Wl,-soname," + path.name, "-o", str(path)]
        else:
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            cmd = ["cc", str(source), "-o", str(path)]
        if runpath is not None:
            cmd.insert(-2, "-Wl,--disable-new-dtags" if legacy_rpath else "-Wl,--enable-new-dtags")
            cmd.insert(-2, "-Wl,-rpath," + runpath)
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as err:
            raise ValidationError(f"synthetic ELF build failed with status {err.returncode}") from err
    path.chmod(0o644 if shared else 0o755)


def populate_valid_synthetic_elves(root):
    primary = root / "usr/share/rustdesk/rustdesk"
    service_child = root / "usr/share/rustdesk/rustdesk-service-child"
    build_synthetic_elf(primary, "$ORIGIN/lib")
    shutil.copyfile(primary, service_child)
    primary.chmod(0o755)
    service_child.chmod(0o711)
    for name in sorted(FLUTTER_LIBRARIES | {NATIVE_XDO_LIBRARY}):
        basename = Path(name).name
        runpath = "$ORIGIN" if basename == "libflutter_linux_gtk.so" or basename.endswith("_plugin.so") else None
        build_synthetic_elf(root / name[2:], runpath, shared=True)


def chown_tree(root, uid, gid):
    if os.geteuid() != 0:
        return
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        os.chown(path, uid, gid, follow_symlinks=False)
    os.chown(root, uid, gid)


def write_synthetic_md5sums(staging):
    lines = []
    for path in sorted(staging.rglob("*"), key=lambda item: os.fsencode(str(item.relative_to(staging)))):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(staging).as_posix()
        if relative.startswith("DEBIAN/") or f"./{relative}" in CONFFILE_PATHS:
            continue
        digest = hashlib.md5()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  /{relative}\n")
    write_file(staging / "DEBIAN/md5sums", "".join(lines), 0o644)


def build_deb(staging, output, root_owner_group, regenerate_md5=True):
    if regenerate_md5:
        write_synthetic_md5sums(staging)
    cmd = ["dpkg-deb"]
    if root_owner_group:
        cmd.append("--root-owner-group")
    cmd.extend(["-b", str(staging), str(output)])
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        diagnostics = err.output.decode("utf-8", errors="replace")[:8192]
        raise ValidationError(f"synthetic dpkg-deb build failed with status {err.returncode}: {diagnostics}") from err


def rewrite_tar_stream(data, transform=None, additions=()):
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as source:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as destination:
            for original in source.getmembers():
                member = copy.copy(original)
                contents = None
                if original.isfile():
                    extracted = source.extractfile(original)
                    if extracted is None:
                        raise ValidationError(f"cannot read synthetic archive member {original.name}")
                    contents = extracted.read()
                result = (member, contents) if transform is None else transform(
                    normalize_tar_name(original.name), member, contents
                )
                if result is None:
                    continue
                member, contents = result
                member.size = len(contents) if member.isfile() and contents is not None else 0
                destination.addfile(member, io.BytesIO(contents) if member.isfile() else None)
            for member, contents in additions:
                member = copy.copy(member)
                member.size = len(contents) if member.isfile() else 0
                destination.addfile(member, io.BytesIO(contents) if member.isfile() else None)
    return output.getvalue()


def gzip_bytes(data):
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressor:
        compressor.write(data)
    return output.getvalue()


def ar_member(name, contents):
    header = (
        f"{name + '/':<16}{0:<12}{0:<6}{0:<6}"
        f"{format(0o100644, 'o'):<8}{len(contents):<10}`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise ValidationError("synthetic ar header has an invalid size")
    return header + contents + (b"\n" if len(contents) % 2 else b"")


def write_deb_from_tar_streams(control, data, output):
    contents = b"!<arch>\n"
    contents += ar_member("debian-binary", b"2.0\n")
    contents += ar_member("control.tar.gz", gzip_bytes(control))
    contents += ar_member("data.tar.gz", gzip_bytes(data))
    with output.open("xb") as package:
        package.write(contents)


def write_modified_deb(
    base_deb,
    output,
    control_transform=None,
    data_transform=None,
    control_additions=(),
    data_additions=(),
):
    control = rewrite_tar_stream(
        tar_stream_from_deb(base_deb, "--ctrl-tarfile"),
        transform=control_transform,
        additions=control_additions,
    )
    data = rewrite_tar_stream(
        tar_stream_from_deb(base_deb, "--fsys-tarfile"),
        transform=data_transform,
        additions=data_additions,
    )
    write_deb_from_tar_streams(control, data, output)


def tar_member_header_offset(data, target, purpose):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        matches = [member for member in archive.getmembers() if normalize_tar_name(member.name) == target]
        if len(matches) != 1:
            raise ValidationError(f"cannot locate one tar member for {purpose}: {target}")
        return matches[0].offset


def rewrite_tar_checksum(mutated, offset):
    mutated[offset + 148:offset + 156] = b"        "
    checksum = sum(mutated[offset:offset + 512])
    checksum_field = f"{checksum:06o}\0 ".encode("ascii")
    if len(checksum_field) != 8:
        raise ValidationError("mutated tar checksum has an invalid size")
    mutated[offset + 148:offset + 156] = checksum_field


def add_hidden_tar_field_padding(data, target, field_offset, field_size, field_name):
    mutated = bytearray(data)
    offset = tar_member_header_offset(data, target, f"raw-{field_name} mutation")
    field = mutated[offset + field_offset:offset + field_offset + field_size]
    nul = field.find(b"\0")
    if nul < 0 or nul + 1 >= len(field) or field[nul + 1] != 0:
        raise ValidationError(f"tar member lacks canonical {field_name} padding for mutation: {target}")
    mutated[offset + field_offset + nul + 1] = ord("X")
    rewrite_tar_checksum(mutated, offset)
    return bytes(mutated)


def replace_tar_type_flag(data, target, type_flag):
    if len(type_flag) != 1:
        raise ValidationError("replacement tar type flag must contain one byte")
    mutated = bytearray(data)
    offset = tar_member_header_offset(data, target, "raw-type mutation")
    mutated[offset + 156:offset + 157] = type_flag
    rewrite_tar_checksum(mutated, offset)
    return bytes(mutated)


def regular_tar_member(name, contents, mode=0o644):
    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mode = mode
    member.size = len(contents)
    return member, contents


def linked_tar_member(name, target, symbolic):
    member = tarfile.TarInfo(name)
    member.type = tarfile.SYMTYPE if symbolic else tarfile.LNKTYPE
    member.linkname = target
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mode = 0o777
    return member, b""


def directory_tar_member(name, mode=0o755):
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mode = mode
    return member, b""


def special_tar_member(name):
    member = tarfile.TarInfo(name)
    member.type = tarfile.FIFOTYPE
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mode = 0o644
    return member, b""


def replace_tar_member(
    target,
    mode=None,
    contents=None,
    remove=False,
    replacement_name=None,
    linkname=None,
):
    def transform(name, member, original_contents):
        if name != target:
            return member, original_contents
        if remove:
            return None
        if replacement_name is not None:
            member.name = replacement_name
        if mode is not None:
            member.mode = mode
        if linkname is not None:
            member.linkname = linkname
        if contents is not None:
            original_contents = contents
        return member, original_contents

    return transform


def elf_dynamic_test_layout(contents):
    program_offset = struct.unpack_from("<Q", contents, 32)[0]
    program_entry_size = struct.unpack_from("<H", contents, 54)[0]
    program_count = struct.unpack_from("<H", contents, 56)[0]
    dynamic_headers = []
    load_segments = []
    program_headers = []
    for index in range(program_count):
        entry_offset = program_offset + index * program_entry_size
        header = struct.unpack_from("<IIQQQQQQ", contents, entry_offset)
        program_headers.append((entry_offset, header))
        if header[0] == 1:
            load_segments.append((header[2], header[3], header[5]))
        elif header[0] == 2:
            dynamic_headers.append((entry_offset, header))
    if len(dynamic_headers) != 1:
        raise ValidationError("synthetic ELF does not contain one dynamic program header")
    dynamic_header, dynamic = dynamic_headers[0]
    entries = []
    for entry_offset in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from("<QQ", contents, entry_offset)
        entries.append((entry_offset, tag, value))
        if tag == 0:
            break
    string_entries = [entry for entry in entries if entry[1] == 5]
    size_entries = [entry for entry in entries if entry[1] == 10]
    if len(string_entries) != 1 or len(size_entries) != 1:
        raise ValidationError("synthetic ELF dynamic string-table tags are not unique")
    string_address = string_entries[0][2]
    string_size = size_entries[0][2]
    string_loads = [
        segment for segment in load_segments
        if string_address >= segment[1]
        and string_address + string_size <= segment[1] + segment[2]
    ]
    if len(string_loads) != 1:
        raise ValidationError("synthetic ELF dynamic string table is not file-backed")
    string_offset = string_loads[0][0] + string_address - string_loads[0][1]
    return {
        "dynamic_header": dynamic_header,
        "dynamic_offset": dynamic[2],
        "dynamic_size": dynamic[5],
        "program_headers": program_headers,
        "entries": entries,
        "string_entry": string_entries[0],
        "size_entry": size_entries[0],
        "string_offset": string_offset,
        "string_size": string_size,
    }


def expect_validation_failure(
    deb,
    expected,
    expected_systemd_unit=None,
    expected_polkit_policy=None,
):
    try:
        validate_deb(deb, expected_systemd_unit, expected_polkit_policy)
    except ValidationError as err:
        if expected in str(err):
            return
        raise ValidationError(f"{deb}: failed for {err!s}, expected failure containing {expected!r}") from err
    raise ValidationError(f"{deb}: verifier accepted an invalid package")


def expect_operation_failure(operation, expected):
    try:
        operation()
    except RuntimeError as err:
        if expected in str(err):
            return
        raise ValidationError(f"operation failed for {err!s}, expected {expected!r}") from err
    raise ValidationError("production Debian staging accepted an invalid tree")


def expect_runpath_failure(dynamic_entries, string_table, expected, name="./usr/share/rustdesk/lib/librustdesk.so"):
    try:
        actual, present = dynamic_runpath(dynamic_entries, string_table, name, "synthetic-runpath")
        validate_runpath_policy(actual, present, name, "synthetic-runpath")
    except ValidationError as err:
        if expected in str(err):
            return
        raise ValidationError(f"RUNPATH parser failed for {err!s}, expected {expected!r}") from err
    raise ValidationError("RUNPATH parser accepted an invalid dynamic-tag inventory")


def load_build_module(repo):
    path = repo / "build.py"
    try:
        source = path.read_bytes()
        code = compile(source, str(path), "exec", dont_inherit=True)
    except (OSError, SyntaxError) as err:
        raise ValidationError("cannot load build.py for Debian staging behavior proof") from err
    module = types.ModuleType("rustdesk_build_authority")
    module.__file__ = str(path)
    exec(code, module.__dict__)
    return module


def require_native_fixture_principal():
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    if (os.geteuid() == 0 or os.getegid() == 0 or status.get("NoNewPrivs", "").strip() != "1"
            or any(int(status.get(name, "1"), 16) for name in
                   ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))):
        raise ValidationError("Debian native fixtures require non-root, no capabilities and no-new-privileges")


def run_elf_role_self_test():
    require_native_fixture_principal()
    subprocess.run(["/bin/bash", str(Path(__file__).with_name("verify-vm-entry-preflight.sh"))],
                   check=True, stdout=subprocess.DEVNULL)
    baseline_sha = "1da47d4ea90bc8901a92c4cc7ef4bf6a94a7f1b1dc6f1127e7429ca0ea2b49c0"
    descriptor = os.open(Path(__file__).with_name("debian-elf-role-baseline.py"),
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1048576:
            raise ValidationError("ELF role baseline is not a bounded regular source")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            source = stream.read(1048577)
        if len(source) != before.st_size or hashlib.sha256(source).hexdigest() != baseline_sha:
            raise ValidationError("ELF role baseline digest differs")
        if os.fstat(descriptor) != before:
            raise ValidationError("ELF role baseline changed")
    finally:
        os.close(descriptor)
    baseline = types.ModuleType("debian_elf_role_baseline")
    baseline.__file__ = "debian-elf-role-baseline.py"
    exec(compile(source, baseline.__file__, "exec", dont_inherit=True), baseline.__dict__)

    library_name = "./usr/share/rustdesk/data/flutter_assets/libm.so.6"
    library = Path("/lib/x86_64-linux-gnu/libm.so.6").read_bytes()
    layout = elf_dynamic_test_layout(library)
    terminator = layout["entries"][-1]
    if (terminator[1:] != (0, 0)
            or terminator[0] + 32 > layout["dynamic_offset"] + layout["dynamic_size"]
            or library[terminator[0] + 16:terminator[0] + 32] != bytes(16)):
        raise ValidationError("native library lacks a spare dynamic entry for PIE fixture")
    pie = bytearray(library)
    struct.pack_into("<QQ", pie, terminator[0], 0x6FFFFFFB, 0x08000000)
    runner = Path("/usr/bin/true").read_bytes()
    fixed_runner = bytearray(runner)
    struct.pack_into("<H", fixed_runner, 16, 2)
    artifacts = []
    entry_artifacts = []
    with tempfile.TemporaryDirectory(prefix="debian-elf-roles.") as scratch:
        scratch = Path(scratch)
        for name, payload in (("shared", library), ("pie", bytes(pie))):
            tree = scratch / name
            write_file(tree / "DEBIAN/control",
                       "Package: rustdesk-elf-fixture\nVersion: 1\nArchitecture: amd64\n"
                       "Maintainer: fixture <fixture@example.invalid>\nDescription: ELF partition fixture\n", 0o644)
            (tree / "DEBIAN").chmod(0o755)
            target = tree / library_name[2:]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(0o400)
            package = scratch / (name + ".deb")
            build_deb(tree, package, root_owner_group=True)
            data = tar_stream_from_deb(package, "--fsys-tarfile")
            members = tar_members_from_stream(data, str(package))
            actual = archive_member_bytes(data, members[library_name], str(package))
            if actual != payload or (members[library_name].uid, members[library_name].gid) != (0, 0):
                raise ValidationError("Debian ELF fixture bytes or archive principal differ")
            artifacts.append(hashlib.sha256(package.read_bytes()).hexdigest())
            baseline.validate_elf_runpaths(package, data, members)
            if name == "shared":
                validate_elf_runpaths(package, data, members)
                loaded = ctypes.CDLL(str(target))
                loaded.cos.argtypes = [ctypes.c_double]
                loaded.cos.restype = ctypes.c_double
                if loaded.cos(0.0) != 1.0:
                    raise ValidationError("native shared-library function differs")
            else:
                try:
                    validate_elf_runpaths(package, data, members)
                except ValidationError as err:
                    if "ELF shared object is marked DF_1_PIE" not in str(err):
                        raise
                else:
                    raise ValidationError("PIE-marked shared library was admitted")
                try:
                    ctypes.CDLL(str(target))
                except OSError as err:
                    if "cannot dynamically load position-independent executable" not in str(err):
                        raise
                else:
                    raise ValidationError("native loader admitted the PIE fixture")

        program_offset = struct.unpack_from("<Q", runner, 32)[0]
        program_count = struct.unpack_from("<H", runner, 56)[0]
        non_executable_loads = [
            header[3] for index in range(program_count)
            if (header := struct.unpack_from("<IIQQQQQQ", runner, program_offset + 56 * index))[0] == 1
            and not header[1] & 1 and header[3] != 0 and header[5] != 0
        ]
        if not non_executable_loads:
            raise ValidationError("native runner lacks a non-executable file-backed load segment")
        for label, entry in (("valid", None), ("zero", 0),
                             ("data", non_executable_loads[0]), ("unmapped", 0x100000000)):
            payload = bytearray(runner)
            if entry is not None:
                struct.pack_into("<Q", payload, 24, entry)
                baseline.validate_elf_identity(payload, PRIMARY_BINARY, PRIMARY_BINARY)
                for name in RUNNER_BINARIES:
                    try:
                        validate_elf_identity(payload, name, name)
                    except ValidationError as err:
                        if "ELF runner entry is not in one file-backed executable load segment" not in str(err):
                            raise
                    else:
                        raise ValidationError(f"invalid {label} runner entry was admitted")
                entry_artifacts.append(hashlib.sha256(payload).hexdigest())
            target = scratch / ("entry-" + label)
            target.write_bytes(payload)
            target.chmod(0o500)
            result = subprocess.run(["/usr/bin/prlimit", "--core=0", "--", str(target)],
                                    cwd=scratch, stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=5, check=False)
            expected = 0 if entry is None else -signal.SIGSEGV
            if result.returncode != expected or result.stdout or result.stderr:
                raise ValidationError(f"native {label} runner entry result differs: {result.returncode}")

        for payload in (runner, bytes(fixed_runner)):
            for name in RUNNER_BINARIES:
                validate_elf_identity(payload, name, name)
        baseline.validate_elf_identity(fixed_runner, PRIMARY_BINARY, PRIMARY_BINARY)
        try:
            baseline.validate_elf_identity(fixed_runner, SERVICE_CHILD_BINARY, SERVICE_CHILD_BINARY)
        except baseline.ValidationError as err:
            if "expected ET_DYN" not in str(err):
                raise
        else:
            raise ValidationError("baseline did not reproduce the service-child role mismatch")
        invalid = bytearray(runner)
        struct.pack_into("<H", invalid, 16, 1)
        for name in RUNNER_BINARIES:
            try:
                validate_elf_identity(invalid, name, name)
            except ValidationError as err:
                if "expected ET_EXEC or ET_DYN" not in str(err):
                    raise
            else:
                raise ValidationError("relocatable runner was admitted")
        invalid_library = bytearray(library)
        struct.pack_into("<H", invalid_library, 16, 2)
        try:
            validate_elf_identity(invalid_library, library_name, library_name)
        except ValidationError as err:
            if "expected ET_DYN" not in str(err):
                raise
        else:
            raise ValidationError("ET_EXEC library was admitted")
    print("DEBIAN_ELF_ROLES=pass cases=9 packages=2 gate=elf-partition "
          "old-pie=accepted current-pie=refused native-dlopen=refused "
          "shared-call=pass runners=types-metadata entry=valid-exit0-invalid-SIGSEGV product=unexecuted cleanup=joined")
    print("DEBIAN_ELF_ROLE_ARTIFACTS=" + json.dumps({
        "baseline_sha256": baseline_sha, "packages_sha256": artifacts,
        "library_sha256": hashlib.sha256(library).hexdigest(),
        "pie_sha256": hashlib.sha256(pie).hexdigest(),
        "runner_sha256": hashlib.sha256(runner).hexdigest(),
        "entry_variants_sha256": entry_artifacts,
    }, sort_keys=True, separators=(",", ":")))


def run_polkit_dependency_self_test(repo):
    require_native_fixture_principal()
    build_module = load_build_module(repo)
    with tempfile.TemporaryDirectory(prefix="rustdesk-polkit-dependency.") as scratch:
        scratch = Path(scratch)
        generated = scratch / "generated-control"
        build_module.generate_control_file("1.0", generated)
        contents = generated.read_text(encoding="utf-8")
        cases = (
            ("production", contents, True),
            ("folded", contents.replace(", polkitd,", ",\n polkitd,"), True),
            ("missing", contents.replace(", polkitd,", ","), False),
            ("recommendation", contents.replace(", polkitd,", ",").replace(
                "Recommends: ", "Recommends: polkitd, "), False),
            ("library", contents.replace(", polkitd,", ", libpolkit-gobject-1-0,"), False),
            ("alternative", contents.replace(", polkitd,", ", polkitd | libc6,"), False),
            ("prefix", contents.replace(", polkitd,", ", polkitd-test,"), False),
        )
        artifacts = []
        for name, control, allowed in cases:
            tree = scratch / name
            write_file(tree / "DEBIAN/control", control, 0o644)
            (tree / "DEBIAN").chmod(0o755)
            deb = scratch / f"{name}.deb"
            build_deb(tree, deb, root_owner_group=True, regenerate_md5=False)
            artifacts.append(hashlib.sha256(deb.read_bytes()).hexdigest())
            stream = tar_stream_from_deb(deb, "--ctrl-tarfile")
            members = tar_members_from_stream(stream, str(deb))
            actual = archive_member_bytes(stream, members["./control"], str(deb))
            if allowed:
                validate_polkit_dependency(actual, str(deb))
            else:
                try:
                    validate_polkit_dependency(actual, str(deb))
                except ValidationError as err:
                    if "required standalone polkitd dependency is absent" not in str(err):
                        raise
                else:
                    raise ValidationError(f"accepted invalid dependency metadata: {name}")
        print("DEBIAN_POLKIT_DEPENDENCY=pass cases=7 generator=production artifacts=actual-deb policy=standalone-depends receiver=unexecuted")
        print("DEBIAN_POLKIT_ARTIFACTS=sha256 " + " ".join(artifacts))
    run_desktop_resource_self_test(repo)


def run_desktop_resource_self_test(repo):
    build_module = load_build_module(repo)
    retired = ("etc/rustdesk/startwm.sh", "etc/rustdesk/xorg.conf")
    with tempfile.TemporaryDirectory(prefix="rustdesk-package-resources.") as scratch:
        scratch = Path(scratch)
        staging = scratch / "tree"
        policy = (f'<policyconfig><action id="{POLKIT_ACTION_ID}"><defaults>'
                  '<allow_any>auth_admin</allow_any>'
                  '<allow_inactive>auth_admin</allow_inactive>'
                  '<allow_active>auth_admin</allow_active>'
                  '</defaults></action></policyconfig>\n').encode("ascii")
        make_synthetic_tree(staging, policy)
        source_scripts = scratch / "scripts"
        source_scripts.mkdir(mode=0o700)
        for name in build_module.DEBIAN_MAINTAINER_SCRIPTS:
            shutil.copyfile(staging / "DEBIAN" / name, source_scripts / name)
        shutil.rmtree(staging / "DEBIAN")
        build_module.stage_debian_control_files("1.0", source_scripts, staging / "DEBIAN")
        build_module.finalize_debian_package_tree(staging)
        produced = scratch / "resources.deb"
        archive = subprocess.run(
            [sys.executable, "-B", "-I", "-S", "-c",
             "import runpy,sys; module=runpy.run_path(sys.argv[1]); "
             "module['build_debian_archive'](sys.argv[2], sys.argv[3])",
             str(repo / "build.py"), str(staging), str(produced)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if archive.returncode:
            raise ValidationError(f"production archive builder failed: {archive.stdout[:8192]!r}")
        digest = hashlib.sha256(produced.read_bytes()).hexdigest()
        data = tar_stream_from_deb(produced, "--fsys-tarfile")
        members = tar_members_from_stream(data, str(produced))
        control = tar_stream_from_deb(produced, "--ctrl-tarfile")
        controls = tar_members_from_stream(control, str(produced))
        conffiles = archive_member_bytes(control, controls["./conffiles"], str(produced))
        if ("./etc/rustdesk" in members
                or any("./" + name in members or ("/" + name).encode() in conffiles
                       for name in retired)):
            raise ValidationError(f"obsolete desktop resources remain in package sha256={digest}")
        validate_data_members(members, str(produced))
        validate_control_members(controls, str(produced))
        for path, (kind, mode) in DATA_REQUIRED.items():
            require_member(members, path, kind, mode, str(produced))
        for path, target in DATA_REQUIRED_SYMLINKS.items():
            require_symlink(members, path, target, str(produced))
        validate_conffiles(control, controls, str(produced))
        validate_md5sums(data, members, control, controls, str(produced))
        if conffiles != b"/etc/init.d/rustdesk\n":
            raise ValidationError("retained init-script conffile differs")

        admission_repo = scratch / "admission-source"
        write_file(admission_repo / POLKIT_POLICY_SOURCE, policy.decode("ascii"), 0o644)
        unit = staging / "usr/lib/systemd/system/rustdesk.service"
        write_file(admission_repo / "res/rustdesk.service", unit.read_text(), 0o644)
        shutil.copyfile(repo / "build.py", admission_repo / "build.py")
        write_file(admission_repo / "Cargo.toml", "[profile.release]\nrpath = false\n", 0o644)
        write_file(admission_repo / "flutter/linux/CMakeLists.txt",
                   'BUILD_WITH_INSTALL_RPATH TRUE\nINSTALL_RPATH "$ORIGIN"\n', 0o644)
        write_file(admission_repo / "scripts/build-debian.sh",
                   "export CARGO_PROFILE_RELEASE_RPATH=false\n", 0o644)
        baseline = Path(__file__).with_name("debian-package-cli-baseline.py")
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-S", str(baseline), "--repo", str(admission_repo),
             "--deb", str(produced)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if (result.returncode != 1
                or b"must contain only the Debian archiver and PE canonicalizer process launches" not in result.stdout
                or b"Traceback" in result.stdout):
            raise ValidationError(f"historical source-gate observation differs: {result.stdout[:8192]!r}")
        write_file(admission_repo / "build.py",
                   'raise RuntimeError("producer executed during archive admission")\n', 0o644)
        command = [sys.executable, "-B", "-I", "-S", str(Path(__file__).resolve()),
                   "--repo", str(admission_repo)]
        cases = (
            ((), 2, b"provide --deb or select a self-test"),
            (("--deb", str(produced)), 1, b"required runtime object is not ELF"),
        )
        for arguments, expected_status, expected_error in cases:
            result = subprocess.run(command + list(arguments),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if (result.returncode != expected_status or result.stdout.count(expected_error) != 1
                    or b"producer executed" in result.stdout or b"Traceback" in result.stdout):
                raise ValidationError(f"package CLI result differs: {result.returncode} {result.stdout[:8192]!r}")
        write_file(admission_repo / "res/rustdesk.service", "unexpected unit\n", 0o644)
        result = subprocess.run(command + ["--deb", str(produced)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if (result.returncode != 1 or b"bytes differ from res/rustdesk.service" not in result.stdout
                or b"producer executed" in result.stdout or b"Traceback" in result.stdout):
            raise ValidationError(f"package CLI failed to bind unit bytes: {result.stdout[:8192]!r}")

        for index, name in enumerate(retired):
            restored = scratch / f"restored-{index}"
            shutil.copytree(staging, restored, symlinks=True)
            (restored / "DEBIAN/md5sums").unlink()
            write_file(restored / name, "retired resource\n", 0o644)
            expect_operation_failure(
                lambda: build_module.finalize_debian_package_tree(restored),
                "data inventory differs",
            )
            restored_deb = scratch / f"restored-{index}.deb"
            write_modified_deb(produced, restored_deb, data_additions=(
                directory_tar_member("./etc/rustdesk"),
                regular_tar_member("./" + name, b"retired resource\n"),
            ))
            restored_data = tar_stream_from_deb(restored_deb, "--fsys-tarfile")
            try:
                validate_data_members(tar_members_from_stream(restored_data, str(restored_deb)),
                                      str(restored_deb))
            except ValidationError as err:
                if "unexpected" not in str(err):
                    raise
            else:
                raise ValidationError(f"archive accepted retired resource {name}")
            restored_conffile = scratch / f"conffile-{index}.deb"
            write_modified_deb(produced, restored_conffile, control_transform=replace_tar_member(
                "./conffiles", contents=conffiles + ("/" + name + "\n").encode("ascii"),
            ))
            stream = tar_stream_from_deb(restored_conffile, "--ctrl-tarfile")
            try:
                validate_conffiles(stream, tar_members_from_stream(stream, str(restored_conffile)),
                                   str(restored_conffile))
            except ValidationError as err:
                if "exact configuration inventory" not in str(err):
                    raise
            else:
                raise ValidationError(f"archive accepted retired conffile {name}")
        print("DEBIAN_DESKTOP_RESOURCES=pass cases=7 generator=production artifacts=actual-deb retained=exact-inventory retired=absent reintroduction=refused product=unexecuted")
        print("DEBIAN_DESKTOP_RESOURCES_ARTIFACT=sha256 " + digest)
        print("DEBIAN_PACKAGE_CLI=pass cases=4 inputs=archives producer=unexecuted empty=refused unit=bound invalid-elf=refused historical-source-gate=blocks-artifact")


def run_production_finalizer_self_test(repo, tmp, polkit_policy):
    build_module = load_build_module(repo)
    staging = tmp / "private-production-tree"
    make_synthetic_tree(staging, polkit_policy)
    populate_valid_synthetic_elves(staging)

    source_scripts = tmp / "private-source-scripts"
    source_scripts.mkdir(mode=0o700)
    for name in ("preinst", "postinst", "prerm", "postrm"):
        source = staging / f"DEBIAN/{name}"
        write_file(source_scripts / name, source.read_text(encoding="utf-8"), 0o700)
    shutil.rmtree(staging / "DEBIAN")

    for path in sorted(staging.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o700)
        else:
            relative = path.relative_to(staging).as_posix()
            path.chmod(0o700 if relative in build_module.DEBIAN_DATA_EXECUTABLES else 0o600)
    staging.chmod(0o700)

    old_umask = os.umask(0o077)
    try:
        build_module.stage_debian_control_files(
            "1.0", source_scripts, staging / "DEBIAN"
        )
        build_module.finalize_debian_package_tree(staging)
    finally:
        os.umask(old_umask)

    if stat.S_IMODE(os.lstat(staging).st_mode) != 0o755:
        raise ValidationError("production finalizer did not make the package root mode 0755")
    for path in staging.rglob("*"):
        relative = path.relative_to(staging).as_posix()
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode):
            expected = 0o755
        elif stat.S_ISLNK(info.st_mode):
            expected = 0o777
        elif relative.startswith("DEBIAN/"):
            expected = build_module.DEBIAN_CONTROL_MODES[relative[len("DEBIAN/"):]]
        else:
            expected = build_module.DEBIAN_DATA_MODES.get(relative, 0o644)
        if stat.S_IMODE(info.st_mode) != expected:
            raise ValidationError(
                f"production finalizer left {relative} mode {stat.S_IMODE(info.st_mode):o}, expected {expected:o}"
            )

    produced = tmp / "production-finalizer.deb"
    build_deb(staging, produced, root_owner_group=True, regenerate_md5=False)
    validate_deb(produced, expected_polkit_policy=polkit_policy)

    unexpected = tmp / "unexpected-control"
    shutil.copytree(staging, unexpected, symlinks=True)
    (unexpected / "DEBIAN/md5sums").unlink()
    write_file(unexpected / "DEBIAN/triggers", "interest rustdesk-invalid\n", 0o600)
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(unexpected),
        "control inventory differs",
    )

    linked = tmp / "linked-payload"
    shutil.copytree(staging, linked, symlinks=True)
    (linked / "DEBIAN/md5sums").unlink()
    os.link(linked / "etc/init.d/rustdesk", linked / "etc/init.d/hardlink")
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(linked),
        "special file or hardlink",
    )

    unexpected_data = tmp / "unexpected-data"
    shutil.copytree(staging, unexpected_data, symlinks=True)
    (unexpected_data / "DEBIAN/md5sums").unlink()
    write_file(unexpected_data / "usr/share/rustdesk/unexpected", "unexpected\n", 0o600)
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(unexpected_data),
        "data inventory differs",
    )

    missing_command_link = tmp / "missing-command-link"
    shutil.copytree(staging, missing_command_link, symlinks=True)
    (missing_command_link / "DEBIAN/md5sums").unlink()
    (missing_command_link / "usr/bin/rustdesk").unlink()
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(missing_command_link),
        "missing symlinks ['usr/bin/rustdesk']",
    )

    wrong_command_link = tmp / "wrong-command-link"
    shutil.copytree(staging, wrong_command_link, symlinks=True)
    (wrong_command_link / "DEBIAN/md5sums").unlink()
    (wrong_command_link / "usr/bin/rustdesk").unlink()
    (wrong_command_link / "usr/bin/rustdesk").symlink_to("/usr/share/rustdesk/rustdesk")
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(wrong_command_link),
        "wrong symlinks [('usr/bin/rustdesk', '/usr/share/rustdesk/rustdesk')]",
    )

    extra_command_link = tmp / "extra-command-link"
    shutil.copytree(staging, extra_command_link, symlinks=True)
    (extra_command_link / "DEBIAN/md5sums").unlink()
    (extra_command_link / "usr/bin/remote-control").symlink_to(
        "../share/rustdesk/rustdesk"
    )
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(extra_command_link),
        "unexpected symlinks ['usr/bin/remote-control']",
    )

    hardlinked_command_link = tmp / "hardlinked-command-link"
    shutil.copytree(staging, hardlinked_command_link, symlinks=True)
    (hardlinked_command_link / "DEBIAN/md5sums").unlink()
    os.link(
        hardlinked_command_link / "usr/bin/rustdesk",
        hardlinked_command_link / "usr/bin/remote-control",
        follow_symlinks=False,
    )
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(hardlinked_command_link),
        "special file or hardlink",
    )

    missing_plugin = tmp / "missing-plugin"
    shutil.copytree(staging, missing_plugin, symlinks=True)
    (missing_plugin / "DEBIAN/md5sums").unlink()
    (missing_plugin / "usr/share/rustdesk/lib/libwindow_size_plugin.so").unlink()
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(missing_plugin),
        "missing files ['usr/share/rustdesk/lib/libwindow_size_plugin.so']",
    )

    unexpected_plugin = tmp / "unexpected-plugin"
    shutil.copytree(staging, unexpected_plugin, symlinks=True)
    (unexpected_plugin / "DEBIAN/md5sums").unlink()
    write_file(
        unexpected_plugin / "usr/share/rustdesk/lib/libunexpected_plugin.so",
        "unexpected\n",
        0o600,
    )
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(unexpected_plugin),
        "unexpected files ['usr/share/rustdesk/lib/libunexpected_plugin.so']",
    )

    symlinked_sources = tmp / "symlinked-source-scripts"
    symlinked_sources.symlink_to(source_scripts, target_is_directory=True)
    expect_operation_failure(
        lambda: build_module.stage_debian_control_files(
            "1.0", symlinked_sources, tmp / "symlinked-control"
        ),
        "source is not a directory",
    )

    symlinked_script_sources = tmp / "symlinked-script-sources"
    shutil.copytree(source_scripts, symlinked_script_sources)
    (symlinked_script_sources / "postinst").unlink()
    (symlinked_script_sources / "postinst").symlink_to(source_scripts / "postinst")
    expect_operation_failure(
        lambda: build_module.stage_debian_control_files(
            "1.0", symlinked_script_sources, tmp / "symlinked-script-control"
        ),
        "not a non-hardlinked regular file",
    )

    hardlinked_script_sources = tmp / "hardlinked-script-sources"
    shutil.copytree(source_scripts, hardlinked_script_sources)
    os.link(hardlinked_script_sources / "postinst", tmp / "hardlinked-postinst-peer")
    expect_operation_failure(
        lambda: build_module.stage_debian_control_files(
            "1.0", hardlinked_script_sources, tmp / "hardlinked-script-control"
        ),
        "not a non-hardlinked regular file",
    )


def make_member_stream(names, directories=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name in names:
            member = tarfile.TarInfo(name)
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            member.mode = 0o644
            if name in directories:
                member.type = tarfile.DIRTYPE
            member.size = 0
            archive.addfile(member, io.BytesIO())
    return stream.getvalue()


def expect_member_stream_failure(names, expected, directories=()):
    try:
        tar_members_from_stream(make_member_stream(names, directories), "synthetic-member-stream")
    except ValidationError as err:
        if expected in str(err):
            return
        raise ValidationError(f"archive parsing failed for {err!s}, expected {expected!r}") from err
    raise ValidationError(
        f"archive parser accepted invalid members {names!r}; expected rejection containing {expected!r}"
    )


def run_self_test(repo, polkit_policy):
    if shutil.which("dpkg-deb") is None:
        raise ValidationError("dpkg-deb is required for self-test")
    with tempfile.TemporaryDirectory(prefix="rustdesk-deb-authority.") as tmp:
        tmp = Path(tmp)
        expect_member_stream_failure(("./duplicate", "./duplicate"), "duplicate archive member")
        expect_member_stream_failure(("./../escape",), "non-canonical name")
        expect_member_stream_failure(("/",), "absolute name")
        expect_member_stream_failure(("plain",), "canonical ./ prefix")
        expect_member_stream_failure(("./.",), "non-canonical name")
        expect_member_stream_failure(("./file/",), "non-directory archive member has a trailing slash")
        expect_member_stream_failure(
            ("./directory//",),
            "directory archive member has redundant trailing slashes",
            directories=("./directory//",),
        )
        expect_runpath_failure(
            ((29, 1), (29, 9)),
            b"\0$ORIGIN\0$ORIGIN/lib\0",
            "multiple RUNPATH entries",
        )
        expect_runpath_failure(
            ((29, 0),),
            b"\0",
            "unexpected RUNPATH",
        )
        run_production_finalizer_self_test(repo, tmp, polkit_policy)

        good_tree = tmp / "good-tree"
        make_synthetic_tree(good_tree, polkit_policy)
        populate_valid_synthetic_elves(good_tree)
        good_deb = tmp / "good.deb"
        build_deb(good_tree, good_deb, root_owner_group=True)
        expected_systemd_unit = (
            good_tree / "usr/lib/systemd/system/rustdesk.service"
        ).read_bytes()
        validate_deb(good_deb, expected_systemd_unit, polkit_policy)

        permissive_polkit_policy = polkit_policy.replace(
            b"<allow_active>auth_admin</allow_active>",
            b"<allow_active>yes</allow_active>",
            1,
        )
        if permissive_polkit_policy == polkit_policy:
            raise ValidationError("source polkit fixture has no exact allow_active policy")
        permissive_polkit_deb = tmp / "permissive-polkit.deb"
        write_modified_deb(
            good_deb,
            permissive_polkit_deb,
            data_transform=replace_tar_member(
                POLKIT_POLICY_MEMBER,
                contents=permissive_polkit_policy,
            ),
        )
        expect_validation_failure(permissive_polkit_deb, "defaults are")

        different_polkit_policy = polkit_policy.replace(
            b"Change the RustDesk unattended password",
            b"Rotate the RustDesk unattended password",
            1,
        )
        if different_polkit_policy == polkit_policy:
            raise ValidationError("source polkit fixture has no exact description")
        different_polkit_deb = tmp / "different-polkit.deb"
        write_modified_deb(
            good_deb,
            different_polkit_deb,
            data_transform=replace_tar_member(
                POLKIT_POLICY_MEMBER,
                contents=different_polkit_policy,
            ),
        )
        expect_validation_failure(
            different_polkit_deb,
            f"bytes differ from {POLKIT_POLICY_SOURCE}",
            expected_polkit_policy=polkit_policy,
        )

        readable_service_deb = tmp / "readable-service.deb"
        write_modified_deb(
            good_deb,
            readable_service_deb,
            data_transform=replace_tar_member(
                SERVICE_CHILD_BINARY,
                mode=0o755,
            ),
        )
        expect_validation_failure(readable_service_deb, "mode 755, expected 711")

        mismatched_service_bytes = bytearray(
            (good_tree / PRIMARY_BINARY[2:]).read_bytes()
        )
        mismatched_service_bytes[-1] ^= 1
        mismatched_service_deb = tmp / "mismatched-service-child.deb"
        write_modified_deb(
            good_deb,
            mismatched_service_deb,
            data_transform=replace_tar_member(
                SERVICE_CHILD_BINARY,
                contents=bytes(mismatched_service_bytes),
            ),
        )
        expect_validation_failure(mismatched_service_deb, "not byte-identical")

        wrong_command_target_deb = tmp / "wrong-command-target.deb"
        write_modified_deb(
            good_deb,
            wrong_command_target_deb,
            data_transform=replace_tar_member(
                "./usr/bin/rustdesk",
                linkname="/usr/share/rustdesk/rustdesk",
            ),
        )
        expect_validation_failure(
            wrong_command_target_deb,
            "wrong symlinks [('./usr/bin/rustdesk', '/usr/share/rustdesk/rustdesk')]",
        )

        missing_command_link_deb = tmp / "missing-command-link.deb"
        write_modified_deb(
            good_deb,
            missing_command_link_deb,
            data_transform=replace_tar_member("./usr/bin/rustdesk", remove=True),
        )
        expect_validation_failure(missing_command_link_deb, "data inventory differs")

        regular_command_deb = tmp / "regular-command.deb"
        write_modified_deb(
            good_deb,
            regular_command_deb,
            data_transform=replace_tar_member("./usr/bin/rustdesk", remove=True),
            data_additions=(regular_tar_member(
                "./usr/bin/rustdesk",
                b"#!/bin/sh\nexit 1\n",
                mode=0o644,
            ),),
        )
        expect_validation_failure(regular_command_deb, "data inventory differs")

        wrong_command_mode_deb = tmp / "wrong-command-mode.deb"
        write_modified_deb(
            good_deb,
            wrong_command_mode_deb,
            data_transform=replace_tar_member("./usr/bin/rustdesk", mode=0o755),
        )
        expect_validation_failure(wrong_command_mode_deb, "mode 755, expected 777")

        wrong_systemd_unit_deb = tmp / "wrong-systemd-unit.deb"
        write_modified_deb(
            good_deb,
            wrong_systemd_unit_deb,
            data_transform=replace_tar_member(
                "./usr/lib/systemd/system/rustdesk.service",
                contents=b"[Service]\nExecStart=/usr/bin/false\n",
            ),
        )
        expect_validation_failure(
            wrong_systemd_unit_deb,
            "bytes differ from res/rustdesk.service",
            expected_systemd_unit,
        )

        bad_owner_tree = tmp / "bad-owner-tree"
        shutil.copytree(good_tree, bad_owner_tree, symlinks=True)
        if os.geteuid() == 0:
            chown_tree(bad_owner_tree, 12345, 12345)
        bad_owner_deb = tmp / "bad-owner.deb"
        build_deb(bad_owner_tree, bad_owner_deb, root_owner_group=False)
        expect_validation_failure(bad_owner_deb, "tar owner names are not canonical root/root")

        bad_mode_tree = tmp / "bad-mode-tree"
        shutil.copytree(good_tree, bad_mode_tree, symlinks=True)
        (bad_mode_tree / "usr/share/rustdesk").chmod(0o775)
        bad_mode_deb = tmp / "bad-mode.deb"
        build_deb(bad_mode_tree, bad_mode_deb, root_owner_group=True)
        expect_validation_failure(bad_mode_deb, "mode 775, expected 755")

        private_mode_tree = tmp / "private-mode-tree"
        shutil.copytree(good_tree, private_mode_tree, symlinks=True)
        for path in private_mode_tree.rglob("*"):
            relative = path.relative_to(private_mode_tree).as_posix()
            if relative == "DEBIAN" or relative.startswith("DEBIAN/"):
                continue
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(0o700)
            else:
                path.chmod(0o700 if f"./{relative}" in DATA_EXECUTABLES else 0o600)
        private_mode_deb = tmp / "private-mode.deb"
        build_deb(private_mode_tree, private_mode_deb, root_owner_group=True)
        expect_validation_failure(private_mode_deb, "mode 700, expected 755")

        private_file_deb = tmp / "private-file.deb"
        write_modified_deb(
            good_deb,
            private_file_deb,
            data_transform=replace_tar_member(
                "./usr/lib/systemd/system/rustdesk.service", mode=0o600
            ),
        )
        expect_validation_failure(private_file_deb, "mode 600, expected 644")

        control_mode_deb = tmp / "control-mode.deb"
        write_modified_deb(
            good_deb,
            control_mode_deb,
            control_transform=replace_tar_member("./preinst", mode=0o555),
        )
        expect_validation_failure(control_mode_deb, "mode 555, expected 755")

        extra_control_deb = tmp / "extra-control.deb"
        write_modified_deb(
            good_deb,
            extra_control_deb,
            control_additions=(regular_tar_member("./triggers", b"interest invalid\n"),),
        )
        expect_validation_failure(extra_control_deb, "control inventory differs")

        nested_control_deb = tmp / "nested-control.deb"
        write_modified_deb(
            good_deb,
            nested_control_deb,
            control_additions=(directory_tar_member("./nested/"),),
        )
        expect_validation_failure(nested_control_deb, "control inventory differs")

        for symbolic, label in ((False, "hardlink"), (True, "symlink")):
            linked_deb = tmp / f"{label}.deb"
            write_modified_deb(
                good_deb,
                linked_deb,
                data_additions=(linked_tar_member(
                    f"./usr/share/rustdesk/data/flutter_assets/{label}",
                    "./usr/share/rustdesk/data/icudtl.dat",
                    symbolic,
                ),),
            )
            expect_validation_failure(
                linked_deb,
                (
                    "unexpected symlinks ['./usr/share/rustdesk/data/flutter_assets/symlink']"
                    if symbolic
                    else "package tree must contain only regular files, directories, and the exact command symlink"
                ),
            )

        special_deb = tmp / "special.deb"
        write_modified_deb(
            good_deb,
            special_deb,
            data_additions=(special_tar_member(
                "./usr/share/rustdesk/data/flutter_assets/special"
            ),),
        )
        expect_validation_failure(
            special_deb,
            "package tree must contain only regular files, directories, and the exact command symlink",
        )

        trailing_runner_deb = tmp / "trailing-runner.deb"
        write_modified_deb(
            good_deb,
            trailing_runner_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/rustdesk",
                replacement_name="./usr/share/rustdesk/rustdesk/",
            ),
        )
        expect_validation_failure(trailing_runner_deb, "non-directory archive member has a trailing slash")

        hidden_name_padding_deb = tmp / "hidden-name-padding.deb"
        write_deb_from_tar_streams(
            tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
            add_hidden_tar_field_padding(
                tar_stream_from_deb(good_deb, "--fsys-tarfile"),
                "./usr/share/rustdesk/rustdesk",
                0,
                100,
                "name",
            ),
            hidden_name_padding_deb,
        )
        expect_validation_failure(hidden_name_padding_deb, "nonzero bytes after NUL")

        hidden_uname_padding_deb = tmp / "hidden-uname-padding.deb"
        write_deb_from_tar_streams(
            tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
            add_hidden_tar_field_padding(
                tar_stream_from_deb(good_deb, "--fsys-tarfile"),
                "./usr/share/rustdesk/rustdesk",
                265,
                32,
                "uname",
            ),
            hidden_uname_padding_deb,
        )
        expect_validation_failure(hidden_uname_padding_deb, "nonzero bytes after NUL")

        hidden_link_name_deb = tmp / "hidden-link-name.deb"
        write_deb_from_tar_streams(
            tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
            add_hidden_tar_field_padding(
                tar_stream_from_deb(good_deb, "--fsys-tarfile"),
                "./usr/share/rustdesk/rustdesk",
                157,
                100,
                "linkname",
            ),
            hidden_link_name_deb,
        )
        expect_validation_failure(hidden_link_name_deb, "nonzero bytes after NUL")

        for label, type_flag in (
            ("alternate-regular", b"\0"),
            ("contiguous", b"7"),
            ("gnu-sparse", b"S"),
        ):
            alternate_type_deb = tmp / f"{label}-type.deb"
            write_deb_from_tar_streams(
                tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
                replace_tar_type_flag(
                    tar_stream_from_deb(good_deb, "--fsys-tarfile"),
                    "./usr/share/rustdesk/rustdesk",
                    type_flag,
                ),
                alternate_type_deb,
            )
            expect_validation_failure(alternate_type_deb, "mismatched tar member header")

        missing_runtime_deb = tmp / "missing-runtime.deb"
        write_modified_deb(
            good_deb,
            missing_runtime_deb,
            data_transform=replace_tar_member("./usr/share/rustdesk/rustdesk", remove=True),
        )
        expect_validation_failure(missing_runtime_deb, "data inventory differs")

        missing_plugin_deb = tmp / "missing-plugin.deb"
        write_modified_deb(
            good_deb,
            missing_plugin_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/lib/libwindow_size_plugin.so",
                remove=True,
            ),
        )
        expect_validation_failure(
            missing_plugin_deb,
            "missing files ['./usr/share/rustdesk/lib/libwindow_size_plugin.so']",
        )

        extra_plugin_deb = tmp / "extra-plugin.deb"
        write_modified_deb(
            good_deb,
            extra_plugin_deb,
            data_additions=(regular_tar_member(
                "./usr/share/rustdesk/lib/libunexpected_plugin.so",
                b"unexpected\n",
            ),),
        )
        expect_validation_failure(
            extra_plugin_deb,
            "unexpected files ['./usr/share/rustdesk/lib/libunexpected_plugin.so']",
        )

        substituted_plugin_deb = tmp / "substituted-plugin.deb"
        write_modified_deb(
            good_deb,
            substituted_plugin_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/lib/libwindow_size_plugin.so",
                remove=True,
            ),
            data_additions=(regular_tar_member(
                "./usr/share/rustdesk/lib/libunexpected_plugin.so",
                b"unexpected\n",
            ),),
        )
        expect_validation_failure(
            substituted_plugin_deb,
            "missing files ['./usr/share/rustdesk/lib/libwindow_size_plugin.so']",
        )

        non_elf_runtime_deb = tmp / "non-elf-runtime.deb"
        write_modified_deb(
            good_deb,
            non_elf_runtime_deb,
            data_transform=replace_tar_member("./usr/share/rustdesk/lib/librustdesk.so", contents=b"not ELF\n"),
        )
        expect_validation_failure(non_elf_runtime_deb, "required runtime object is not ELF")

        non_elf_plugin_deb = tmp / "non-elf-plugin.deb"
        write_modified_deb(
            good_deb,
            non_elf_plugin_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/lib/libwindow_size_plugin.so",
                contents=b"not ELF\n",
            ),
        )
        expect_validation_failure(non_elf_plugin_deb, "required runtime object is not ELF")

        good_data_tar = tar_stream_from_deb(good_deb, "--fsys-tarfile")
        good_data_members = tar_members_from_stream(good_data_tar, "good-data")
        librustdesk = archive_member_bytes(
            good_data_tar,
            good_data_members["./usr/share/rustdesk/lib/librustdesk.so"],
            "good-librustdesk",
        )
        dynamic_layout = elf_dynamic_test_layout(librustdesk)
        elf_mutations = []
        wrong_class = bytearray(librustdesk)
        wrong_class[4] = 1
        elf_mutations.append(("wrong-class", bytes(wrong_class), "ELF class is not 64-bit"))
        wrong_endian = bytearray(librustdesk)
        wrong_endian[5] = 2
        elf_mutations.append(("wrong-endian", bytes(wrong_endian), "ELF byte order is not little-endian"))
        wrong_machine = bytearray(librustdesk)
        struct.pack_into("<H", wrong_machine, 18, 3)
        elf_mutations.append(("wrong-machine", bytes(wrong_machine), "ELF machine is not x86-64"))
        relocatable = bytearray(librustdesk)
        struct.pack_into("<H", relocatable, 16, 1)
        elf_mutations.append(("relocatable", bytes(relocatable), "expected ET_DYN"))
        no_dynamic = bytearray(librustdesk)
        dynamic_header = dynamic_layout["dynamic_header"]
        struct.pack_into("<I", no_dynamic, dynamic_header, 0)
        elf_mutations.append(("no-dynamic", bytes(no_dynamic), "exactly one dynamic segment"))

        mismatched_dynamic = bytearray(librustdesk)
        original_dynamic_offset = struct.unpack_from("<Q", mismatched_dynamic, dynamic_header + 8)[0]
        struct.pack_into("<Q", mismatched_dynamic, dynamic_header + 8, original_dynamic_offset + 16)
        elf_mutations.append((
            "mismatched-dynamic",
            bytes(mismatched_dynamic),
            "dynamic segment is not consistently mapped",
        ))

        misaligned_dynamic = bytearray(librustdesk)
        struct.pack_into("<Q", misaligned_dynamic, dynamic_header + 48, 4)
        elf_mutations.append((
            "misaligned-dynamic",
            bytes(misaligned_dynamic),
            "does not have canonical 8-byte alignment",
        ))

        unterminated_dynamic = bytearray(librustdesk)
        dynamic_offset = dynamic_layout["dynamic_offset"]
        dynamic_size = dynamic_layout["dynamic_size"]
        for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
            if struct.unpack_from("<Q", unterminated_dynamic, offset)[0] == 0:
                struct.pack_into("<Q", unterminated_dynamic, offset, 1)
        elf_mutations.append((
            "unterminated-dynamic",
            bytes(unterminated_dynamic),
            "dynamic segment is not DT_NULL-terminated",
        ))

        missing_strtab = bytearray(librustdesk)
        struct.pack_into("<Q", missing_strtab, dynamic_layout["string_entry"][0], 4)
        elf_mutations.append((
            "missing-strtab",
            bytes(missing_strtab),
            "one bounded dynamic string table",
        ))

        duplicate_candidate = next(
            entry for entry in dynamic_layout["entries"]
            if entry[1] not in (0, 5, 10)
        )
        duplicate_strtab = bytearray(librustdesk)
        struct.pack_into("<QQ", duplicate_strtab, duplicate_candidate[0], 5, dynamic_layout["string_entry"][2])
        elf_mutations.append((
            "duplicate-strtab",
            bytes(duplicate_strtab),
            "one bounded dynamic string table",
        ))

        zero_strsz = bytearray(librustdesk)
        struct.pack_into("<Q", zero_strsz, dynamic_layout["size_entry"][0] + 8, 0)
        elf_mutations.append((
            "zero-strsz",
            bytes(zero_strsz),
            "one bounded dynamic string table",
        ))

        unmapped_strtab = bytearray(librustdesk)
        struct.pack_into(
            "<Q",
            unmapped_strtab,
            dynamic_layout["string_entry"][0] + 8,
            0xFFFFFFFFFFFFF000,
        )
        elf_mutations.append((
            "unmapped-strtab",
            bytes(unmapped_strtab),
            "dynamic string table is not mapped",
        ))

        oversized_strtab = bytearray(librustdesk)
        struct.pack_into(
            "<Q",
            oversized_strtab,
            dynamic_layout["size_entry"][0] + 8,
            len(librustdesk) + 1,
        )
        elf_mutations.append((
            "oversized-strtab",
            bytes(oversized_strtab),
            "dynamic string table is not mapped",
        ))

        nonnul_first_strtab = bytearray(librustdesk)
        nonnul_first_strtab[dynamic_layout["string_offset"]] = ord("X")
        elf_mutations.append((
            "nonnul-first-strtab",
            bytes(nonnul_first_strtab),
            "dynamic string table must begin and end with NUL",
        ))

        nonnul_last_strtab = bytearray(librustdesk)
        string_end = dynamic_layout["string_offset"] + dynamic_layout["string_size"]
        nonnul_last_strtab[string_end - 1] = ord("X")
        elf_mutations.append((
            "nonnul-last-strtab",
            bytes(nonnul_last_strtab),
            "dynamic string table must begin and end with NUL",
        ))

        soname_entries = [entry for entry in dynamic_layout["entries"] if entry[1] == 14]
        if len(soname_entries) != 1:
            raise ValidationError("synthetic shared ELF does not contain one SONAME")
        soname_entry = soname_entries[0]
        out_of_bounds_soname = bytearray(librustdesk)
        struct.pack_into(
            "<Q",
            out_of_bounds_soname,
            soname_entry[0] + 8,
            dynamic_layout["string_size"],
        )
        elf_mutations.append((
            "out-of-bounds-soname",
            bytes(out_of_bounds_soname),
            "SONAME string offset is out of bounds",
        ))

        wrong_soname = bytearray(librustdesk)
        soname_string_offset = dynamic_layout["string_offset"] + soname_entry[2]
        wrong_soname[soname_string_offset] = ord("X")
        elf_mutations.append((
            "wrong-soname",
            bytes(wrong_soname),
            "does not match the installed basename",
        ))

        audit_tag = bytearray(librustdesk)
        struct.pack_into("<QQ", audit_tag, duplicate_candidate[0], 0x6FFFFEFC, soname_entry[2])
        elf_mutations.append((
            "audit-tag",
            bytes(audit_tag),
            "forbidden dynamic loader tags",
        ))

        shared_interpreter_candidate = next(
            entry for entry in dynamic_layout["program_headers"]
            if entry[1][0] not in (0, 1, 2, 3, 0x6474E551)
        )
        shared_interpreter = bytearray(librustdesk)
        struct.pack_into("<I", shared_interpreter, shared_interpreter_candidate[0], 3)
        elf_mutations.append((
            "shared-interpreter",
            bytes(shared_interpreter),
            "shared object contains a program interpreter",
        ))

        stack_headers = [
            entry for entry in dynamic_layout["program_headers"]
            if entry[1][0] == 0x6474E551
        ]
        if len(stack_headers) != 1:
            raise ValidationError("synthetic shared ELF does not contain one GNU stack header")
        stack_header = stack_headers[0]

        for label, alignment in (
            ("no-stack-alignment", 0),
            ("dart-stack-alignment", 1),
            ("gnu-stack-alignment", 16),
        ):
            valid_stack_alignment = bytearray(librustdesk)
            struct.pack_into("<Q", valid_stack_alignment, stack_header[0] + 48, alignment)
            validate_elf_identity(
                bytes(valid_stack_alignment),
                "./usr/share/rustdesk/lib/librustdesk.so",
                label,
            )

        missing_stack = bytearray(librustdesk)
        struct.pack_into("<I", missing_stack, stack_header[0], 0)
        elf_mutations.append((
            "missing-stack",
            bytes(missing_stack),
            "must contain exactly one GNU stack header",
        ))

        duplicate_stack = bytearray(librustdesk)
        struct.pack_into("<I", duplicate_stack, shared_interpreter_candidate[0], 0x6474E551)
        elf_mutations.append((
            "duplicate-stack",
            bytes(duplicate_stack),
            "must contain exactly one GNU stack header",
        ))

        for label, field_offset in (
            ("stack-file-offset", 8),
            ("stack-virtual-address", 16),
            ("stack-physical-address", 24),
            ("stack-file-size", 32),
            ("stack-memory-size", 40),
        ):
            nonempty_stack = bytearray(librustdesk)
            struct.pack_into("<Q", nonempty_stack, stack_header[0] + field_offset, 1)
            elf_mutations.append((
                label,
                bytes(nonempty_stack),
                "GNU stack header must not describe file or memory contents",
            ))

        executable_stack = bytearray(librustdesk)
        struct.pack_into("<I", executable_stack, stack_header[0] + 4, stack_header[1][1] | 1)
        elf_mutations.append((
            "executable-stack",
            bytes(executable_stack),
            "GNU stack permissions are not exact non-executable RW",
        ))

        for label, flags in (
            ("read-only-stack", 4),
            ("write-only-stack", 2),
            ("unexpected-stack-flags", 14),
        ):
            wrong_stack_flags = bytearray(librustdesk)
            struct.pack_into("<I", wrong_stack_flags, stack_header[0] + 4, flags)
            elf_mutations.append((
                label,
                bytes(wrong_stack_flags),
                "GNU stack permissions are not exact non-executable RW",
            ))

        invalid_stack_alignment = bytearray(librustdesk)
        struct.pack_into("<Q", invalid_stack_alignment, stack_header[0] + 48, 3)
        elf_mutations.append((
            "invalid-stack-alignment",
            bytes(invalid_stack_alignment),
            "GNU stack alignment is not ABI-valid",
        ))

        writable_load = next(
            entry for entry in dynamic_layout["program_headers"]
            if entry[1][0] == 1 and entry[1][1] & 2
        )
        writable_executable_load = bytearray(librustdesk)
        struct.pack_into(
            "<I",
            writable_executable_load,
            writable_load[0] + 4,
            writable_load[1][1] | 1,
        )
        elf_mutations.append((
            "writable-executable-load",
            bytes(writable_executable_load),
            "load segment is writable and executable",
        ))
        for label, contents, expected in elf_mutations:
            malformed_elf_deb = tmp / f"{label}.deb"
            write_modified_deb(
                good_deb,
                malformed_elf_deb,
                data_transform=replace_tar_member(
                    "./usr/share/rustdesk/lib/librustdesk.so",
                    contents=contents,
                ),
            )
            expect_validation_failure(malformed_elf_deb, expected)

        runner = archive_member_bytes(
            good_data_tar,
            good_data_members["./usr/share/rustdesk/rustdesk"],
            "good-runner",
        )
        runner_layout = elf_dynamic_test_layout(runner)
        interpreter_headers = [
            entry for entry in runner_layout["program_headers"] if entry[1][0] == 3
        ]
        if len(interpreter_headers) != 1:
            raise ValidationError("synthetic runner ELF does not contain one program interpreter")
        interpreter_header = interpreter_headers[0]
        bad_interpreter = bytearray(runner)
        interpreter_offset = interpreter_header[1][2]
        interpreter_size = interpreter_header[1][5]
        replacement_interpreter = b"/tmp/rustdesk-ld.so\0"
        if len(replacement_interpreter) > interpreter_size:
            raise ValidationError("synthetic runner interpreter is too short for mutation")
        bad_interpreter[interpreter_offset:interpreter_offset + interpreter_size] = (
            replacement_interpreter + b"\0" * (interpreter_size - len(replacement_interpreter))
        )

        missing_interpreter = bytearray(runner)
        struct.pack_into("<I", missing_interpreter, interpreter_header[0], 0)

        second_interpreter_candidate = next(
            entry for entry in runner_layout["program_headers"]
            if entry[1][0] not in (0, 1, 2, 3, 0x6474E551)
        )
        second_interpreter = bytearray(runner)
        struct.pack_into("<I", second_interpreter, second_interpreter_candidate[0], 3)

        for label, contents, expected in (
            ("bad-interpreter", bytes(bad_interpreter), "program interpreter is not exact"),
            ("missing-interpreter", bytes(missing_interpreter), "exactly one program interpreter"),
            ("second-interpreter", bytes(second_interpreter), "exactly one program interpreter"),
        ):
            interpreter_deb = tmp / f"{label}.deb"
            write_modified_deb(
                good_deb,
                interpreter_deb,
                data_transform=replace_tar_member(
                    "./usr/share/rustdesk/rustdesk",
                    contents=contents,
                ),
            )
            expect_validation_failure(interpreter_deb, expected)

        needed_entries = [entry for entry in runner_layout["entries"] if entry[1] == 1]
        if not needed_entries:
            raise ValidationError("synthetic runner ELF does not contain a NEEDED entry")
        unsafe_needed = bytearray(runner)
        needed_offset = runner_layout["string_offset"] + needed_entries[0][2]
        needed_end = unsafe_needed.find(b"\0", needed_offset)
        if needed_end - needed_offset < len("/tmp/x.so"):
            raise ValidationError("synthetic runner NEEDED name is too short for mutation")
        unsafe_needed[needed_offset:needed_offset + len("/tmp/x.so")] = b"/tmp/x.so"
        unsafe_needed[needed_offset + len("/tmp/x.so")] = 0
        unsafe_needed_deb = tmp / "unsafe-needed.deb"
        write_modified_deb(
            good_deb,
            unsafe_needed_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/rustdesk",
                contents=bytes(unsafe_needed),
            ),
        )
        expect_validation_failure(unsafe_needed_deb, "NEEDED is not a safe dependency basename")

        unexpected_data_deb = tmp / "unexpected-data.deb"
        write_modified_deb(
            good_deb,
            unexpected_data_deb,
            data_additions=(regular_tar_member("./usr/share/rustdesk/unexpected", b"unexpected\n"),),
        )
        expect_validation_failure(unexpected_data_deb, "data inventory differs")

        bad_runpath = tmp / "bad-runpath.so"
        build_synthetic_elf(bad_runpath, "/tmp/rustdesk-bad", shared=True)
        bad_runpath_deb = tmp / "bad-runpath.deb"
        write_modified_deb(
            good_deb,
            bad_runpath_deb,
            data_additions=(regular_tar_member(
                "./usr/share/rustdesk/data/flutter_assets/bad-runpath.so",
                bad_runpath.read_bytes(),
            ),),
        )
        expect_validation_failure(bad_runpath_deb, "unexpected RUNPATH")

        legacy_rpath = tmp / "legacy-rpath/librustdesk.so"
        legacy_rpath.parent.mkdir()
        build_synthetic_elf(legacy_rpath, "/tmp/rustdesk-legacy", shared=True, legacy_rpath=True)
        legacy_rpath_deb = tmp / "legacy-rpath.deb"
        write_modified_deb(
            good_deb,
            legacy_rpath_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/lib/librustdesk.so",
                contents=legacy_rpath.read_bytes(),
            ),
        )
        expect_validation_failure(legacy_rpath_deb, "legacy RPATH is forbidden")

        bad_conffiles_deb = tmp / "bad-conffiles.deb"
        write_modified_deb(
            good_deb,
            bad_conffiles_deb,
            control_transform=replace_tar_member("./conffiles", contents=b"/etc/init.d/unexpected\n"),
        )
        expect_validation_failure(bad_conffiles_deb, "content differs from the exact configuration inventory")

        md5sums = archive_member_bytes(
            tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
            tar_members_from_deb(good_deb, "--ctrl-tarfile")["./md5sums"],
            "good-md5sums",
        )
        if b"/usr/bin/rustdesk\n" in md5sums:
            raise ValidationError("good md5sums incorrectly contains the package command symlink")
        bad_md5_deb = tmp / "bad-md5.deb"
        write_modified_deb(
            good_deb,
            bad_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums", contents=b"0" * 32 + md5sums[32:]
            ),
        )
        expect_validation_failure(bad_md5_deb, "digest differs")

        malformed_md5_deb = tmp / "malformed-md5.deb"
        write_modified_deb(
            good_deb,
            malformed_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums", contents=md5sums.replace(b"  /", b" /", 1)
            ),
        )
        expect_validation_failure(malformed_md5_deb, "malformed line")

        md5_lines = md5sums.splitlines(keepends=True)
        duplicate_md5_deb = tmp / "duplicate-md5.deb"
        write_modified_deb(
            good_deb,
            duplicate_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums", contents=md5sums + md5_lines[0]
            ),
        )
        expect_validation_failure(duplicate_md5_deb, "duplicate path")

        missing_md5_deb = tmp / "missing-md5.deb"
        write_modified_deb(
            good_deb,
            missing_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums", contents=b"".join(md5_lines[1:])
            ),
        )
        expect_validation_failure(missing_md5_deb, "inventory differs")

        extra_md5_deb = tmp / "extra-md5.deb"
        write_modified_deb(
            good_deb,
            extra_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums",
                contents=md5sums + b"00000000000000000000000000000000  /unexpected\n",
            ),
        )
        expect_validation_failure(extra_md5_deb, "inventory differs")


def main():
    parser = argparse.ArgumentParser(description="Verify Debian package payload authority for the RustDesk root service.")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--deb", action="append", default=[], help="built .deb to validate; may be repeated")
    parser.add_argument("--self-test", action="store_true", help="run synthetic positive and negative package checks")
    parser.add_argument("--polkit-dependency-self-test", action="store_true", help="test production dependency metadata in actual Debian archives")
    parser.add_argument("--elf-role-self-test", action="store_true", help="test ELF roles in Debian archives against the native loader")
    args = parser.parse_args()

    if not (args.deb or args.self_test or args.polkit_dependency_self_test or args.elf_role_self_test):
        parser.error("provide --deb or select a self-test")

    try:
        repo = Path(args.repo).resolve()
        if args.elf_role_self_test:
            if args.self_test or args.deb or args.polkit_dependency_self_test:
                raise ValidationError("ELF role tests cannot be combined with other modes")
            run_elf_role_self_test()
            return
        if args.polkit_dependency_self_test:
            if args.self_test or args.deb:
                raise ValidationError("polkit dependency tests cannot be combined with other modes")
            run_polkit_dependency_self_test(repo)
            return
        polkit_policy = load_polkit_policy(repo)
        if args.self_test:
            run_self_test(repo, polkit_policy)
        expected_systemd_unit = (repo / "res/rustdesk.service").read_bytes() if args.deb else None
        for deb in args.deb:
            validate_deb(
                Path(deb).resolve(),
                expected_systemd_unit,
                polkit_policy,
            )
    except ValidationError as err:
        fail(str(err))

    if args.self_test:
        print("ok  Debian package archive and production-finalizer self-tests passed")
    for deb in args.deb:
        print(f"ok  Debian package archive verified: {deb}")


if __name__ == "__main__":
    main()
